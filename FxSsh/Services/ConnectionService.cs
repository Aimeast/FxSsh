using FxSsh.Messages;
using FxSsh.Messages.Connection;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.Services
{
    public class ConnectionService : SshService, IDynamicInvoker
    {
        private readonly object _locker = new object();
        private readonly List<Channel> _channels = new List<Channel>();
        private readonly UserauthArgs _auth = null;
        private readonly BlockingCollection<ConnectionServiceMessage> _messageQueue =
            new BlockingCollection<ConnectionServiceMessage>(new ConcurrentQueue<ConnectionServiceMessage>());
        private readonly CancellationTokenSource _messageCts = new CancellationTokenSource();

        private int _serverChannelCounter = -1;

        public ConnectionService(Session session, UserauthArgs auth)
            : base(session)
        {
            Contract.Requires(auth != null);

            _auth = auth;

            Task.Run(MessageLoop);
        }

        public event EventHandler<CommandRequestedArgs> CommandOpened;
        public event EventHandler<EnvironmentArgs> EnvReceived;
        public event EventHandler<PtyArgs> PtyReceived;
        public event EventHandler<TcpRequestArgs> TcpForwardRequest;
        public event EventHandler<WindowChangeArgs> WindowChange;

        protected internal override void CloseService()
        {
            _messageCts.Cancel();

            lock (_locker)
            {
                foreach (var channel in _channels.ToArray())
                {
                    channel.ForceClose();
                }
            }
        }

        internal void HandleMessageCore(ConnectionServiceMessage message)
        {
            Contract.Requires(message != null);

            if (message is ChannelWindowAdjustMessage)
                this.InvokeHandleMessage(message);
            else
                _messageQueue.Add(message);
        }

        private void MessageLoop()
        {
            try
            {
                while (true)
                {
                    var message = _messageQueue.Take(_messageCts.Token);
                    this.InvokeHandleMessage(message);
                }
            }
            catch (OperationCanceledException)
            {
            }
        }

        private void HandleMessage(ChannelOpenMessage message)
        {
            switch (message.ChannelType)
            {
                case "session":
                    var msg = Message.LoadFrom<SessionOpenMessage>(message);
                    HandleMessage(msg);
                    break;
                case "direct-tcpip":
                    var tcpMsg = Message.LoadFrom<DirectTcpIpMessage>(message);
                    HandleMessage(tcpMsg);
                    break;
                case "forwarded-tcpip":
                    var forwardMsg = Message.LoadFrom<ForwardedTcpIpMessage>(message);
                    HandleMessage(forwardMsg);
                    break;
                default:
                    _session.SendMessage(new ChannelOpenFailureMessage
                    {
                        RecipientChannel = message.SenderChannel,
                        ReasonCode = ChannelOpenFailureReason.UnknownChannelType,
                        Description = string.Format("Unknown channel type: {0}.", message.ChannelType),
                    });
                    throw new SshConnectionException(string.Format("Unknown channel type: {0}.", message.ChannelType));
            }
        }

        private void HandleMessage(ShouldIgnoreMessage message)
        {
        }

        private void HandleMessage(ForwardedTcpIpMessage message)
        {
            var channel = HandleChannelOpenMessage(message);
            var args = new TcpRequestArgs(channel,
                message.Address,
                (int)message.Port,
                message.OriginatorIPAddress,
                (int)message.OriginatorPort,
                _auth);
            TcpForwardRequest?.Invoke(this, args);
        }

        private void HandleMessage(DirectTcpIpMessage message)
        {
            var channel = HandleChannelOpenMessage(message);
            var args = new TcpRequestArgs(channel,
                message.Host,
                (int)message.Port,
                message.OriginatorIPAddress,
                (int)message.OriginatorPort,
                _auth);
            TcpForwardRequest?.Invoke(this, args);
        }

        private void HandleMessage(ChannelRequestMessage message)
        {
            switch (message.RequestType)
            {
                case "exec":
                    var msg = Message.LoadFrom<CommandRequestMessage>(message);
                    HandleMessage(msg);
                    break;
                case "shell":
                    var shell_msg = Message.LoadFrom<ShellRequestMessage>(message);
                    HandleMessage(shell_msg);
                    break;
                case "pty-req":
                    var pty_msg = Message.LoadFrom<PtyRequestMessage>(message);
                    HandleMessage(pty_msg);
                    break;
                case "env":
                    var env_msg = Message.LoadFrom<EnvMessage>(message);
                    HandleMessage(env_msg);
                    break;
                case "subsystem":
                    var sub_msg = Message.LoadFrom<SubsystemRequestMessage>(message);
                    HandleMessage(sub_msg);
                    break;
                case "window-change":
                    var window_change_msg = Message.LoadFrom<WindowChangeMessage>(message);
                    HandleMessage(window_change_msg);
                    break;
                case "simple@putty.projects.tartarus.org":
                    //https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
                    if (message.WantReply)
                    {
                        var c = FindChannelByServerId<SessionChannel>(message.RecipientChannel);
                        _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = c.ClientChannelId });
                    }
                    break;
                case "winadj@putty.projects.tartarus.org":
                    //https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
                    var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);
                    _session.SendMessage(new ChannelFailureMessage { RecipientChannel = channel.ClientChannelId });
                    break;
                case "auth-agent-req@openssh.com":
                    // https://github.com/openssh/openssh-portable/blob/V_8_0_P1/session.c#L2225
                    break;
                default:
                    if (message.WantReply)
                        _session.SendMessage(new ChannelFailureMessage
                        {
                            RecipientChannel = FindChannelByServerId<Channel>(message.RecipientChannel).ClientChannelId
                        });
                    throw new SshConnectionException(string.Format("Unknown request type: {0}.", message.RequestType));
            }
        }

        private void HandleMessage(EnvMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            EnvReceived?.Invoke(this, new EnvironmentArgs(channel, message.Name, message.Value, _auth));

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(PtyRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            PtyReceived?.Invoke(this,
                new PtyArgs(channel,
                    message.Terminal,
                    message.heightPx,
                    message.heightRows,
                    message.widthPx,
                    message.widthChars,
                    message.modes, _auth));

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(ChannelDataMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnData(message.Data);
        }

        private void HandleMessage(ChannelWindowAdjustMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.ClientAdjustWindow(message.BytesToAdd);
        }

        private void HandleMessage(ChannelEofMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnEof();
        }

        private void HandleMessage(ChannelCloseMessage message)
        {
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnClose();
        }

        private void HandleMessage(SessionOpenMessage message)
        {
            HandleChannelOpenMessage(message);
        }

        private SessionChannel HandleChannelOpenMessage(ChannelOpenMessage message)
        {
            var channel = new SessionChannel(
                this,
                message.SenderChannel,
                message.InitialWindowSize,
                message.MaximumPacketSize,
                (uint)Interlocked.Increment(ref _serverChannelCounter));

            lock (_locker)
                _channels.Add(channel);

            var msg = new ChannelOpenConfirmationMessage
            {
                RecipientChannel = channel.ClientChannelId,
                SenderChannel = channel.ServerChannelId,
                InitialWindowSize = channel.ServerInitialWindowSize,
                MaximumPacketSize = channel.ServerMaxPacketSize
            };

            _session.SendMessage(msg);
            return channel;
        }

        private void HandleMessage(ShellRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "shell", null, _auth));
        }

        private void HandleMessage(CommandRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "exec", message.Command, _auth));
        }

        private void HandleMessage(SubsystemRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });

            CommandOpened?.Invoke(this, new CommandRequestedArgs(channel, "subsystem", message.Name, _auth));
        }

        private void HandleMessage(WindowChangeMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            WindowChange?.Invoke(this, new WindowChangeArgs(channel, message.WidthColumns, message.HeightRows, message.WidthPixels, message.HeightPixels));
        }

        private T FindChannelByClientId<T>(uint id) where T : Channel
        {
            lock (_locker)
            {
                var channel = _channels.FirstOrDefault(x => x.ClientChannelId == id) as T;
                if (channel == null)
                    throw new SshConnectionException(string.Format("Invalid client channel id {0}.", id),
                        DisconnectReason.ProtocolError);

                return channel;
            }
        }

        private T FindChannelByServerId<T>(uint id) where T : Channel
        {
            lock (_locker)
            {
                var channel = _channels.FirstOrDefault(x => x.ServerChannelId == id) as T;
                if (channel == null)
                    throw new SshConnectionException(string.Format("Invalid server channel id {0}.", id),
                        DisconnectReason.ProtocolError);

                return channel;
            }
        }

        internal void RemoveChannel(Channel channel)
        {
            lock (_locker)
            {
                _channels.Remove(channel);
            }
        }
    }
}
