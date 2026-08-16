using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.Connection;

namespace FxSsh.Services
{
    public class ConnectionService : SshService
    {
        private readonly object _locker = new();
        // Keyed by ServerChannelId for O(1) lookup on the data/control hot
        // path (every ChannelDataMessage/WindowAdjust does a find). The old
        // List + FirstOrDefault scan was O(channels) per packet and churned
        // enumerator allocations; with forwarding at n=500 this was a real
        // scalability cost.
        private readonly Dictionary<uint, Channel> _channels = [];
        private readonly UserAuthArgs _auth = null;
        private readonly System.Threading.Channels.Channel<ConnectionServiceMessage> _messageChannel =
            System.Threading.Channels.Channel.CreateUnbounded<ConnectionServiceMessage>(new UnboundedChannelOptions { SingleReader = true });
        private readonly CancellationTokenSource _messageCts = new();

        private int _serverChannelCounter = -1;

        // Reverse port forwarding: one listener per (address, port) the peer
        // requested via "tcpip-forward". Keyed by (address, port) using the
        // bound endpoint the listener actually used (so cancel-tcpip-forward
        // matches against the bound port the peer learned from our SUCCESS).
        private readonly Dictionary<(string address, uint port), PortForwardingService> _forwarders = new();

        public ConnectionService(Session session, UserAuthArgs auth)
            : base(session)
        {
            ArgumentNullException.ThrowIfNull(auth);

            _auth = auth;

            Task.Run(MessageLoopAsync);
        }

        public event EventHandler<CommandRequestedArgs> CommandOpened;
        public event EventHandler<SubsystemRequestedArgs> SubsystemRequested;
        public event EventHandler<EnvironmentArgs> EnvReceived;
        public event EventHandler<PtyArgs> PtyReceived;
        public event EventHandler<TcpRequestArgs> TcpForwardRequest;

        /// <summary>
        /// Raised when the peer requests a reverse port forwarding listener
        /// via SSH_MSG_GLOBAL_REQUEST "tcpip-forward". The host MUST set
        /// args.Accepted = true to permit the listener; default false rejects.
        /// </summary>
        public event EventHandler<TcpForwardRequestArgs> TcpForwardRequestReceived;

        protected internal override void CloseService()
        {
            _messageCts.Cancel();
            _messageChannel.Writer.TryComplete();

            lock (_locker)
            {
                foreach (var channel in _channels.Values.ToArray())
                {
                    channel.ForceClose();
                }

                // Tear down all reverse-forward listeners; their TCP sockets
                // are independent of the SSH session and must not outlive it.
                foreach (var fwd in _forwarders.Values)
                {
                    try { fwd.Dispose(); } catch { }
                }
                _forwarders.Clear();
            }
        }

        internal void HandleMessageCore(ConnectionServiceMessage message)
        {
            ArgumentNullException.ThrowIfNull(message);

            if (message is ChannelWindowAdjustMessage)
                // Window adjust must be processed inline (before the queued
                // messages ahead of it) so send-window accounting stays exact.
                this.HandleMessage((dynamic)message);
            else
            {
                // The queued message's RawBytes is a zero-copy slice over the
                // SSH receive buffer, which is recycled by the next
                // ReceiveMessage. The queue is drained asynchronously, so
                // snapshot the wire bytes now - otherwise LoadFrom<T> would
                // re-parse garbage (e.g. a subsystem request whose type byte
                // became the next message's type).
                message.SnapshotRawBytes();
                if (message is ChannelDataMessage data)
                    data.Data = data.Data.ToArray();
                _messageChannel.Writer.TryWrite(message);
            }
        }

        private async Task MessageLoopAsync()
        {
            try
            {
                await foreach (var message in _messageChannel.Reader.ReadAllAsync(_messageCts.Token))
                {
                    try
                    {
                        this.HandleMessage((dynamic)message);
                    }
                    catch (Exception ex)
                    {
                        // A single malformed/hostile message must not kill the
                        // whole channel-processing loop silently.
                        Log.Fail($"Connection service message handling failed: {ex}");
                    }
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
                    Log.Warn($"Unknown channel type: {message.ChannelType}.");
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

        /// <summary>
        /// Handle SSH_MSG_GLOBAL_REQUEST "tcpip-forward" / "cancel-tcpip-forward"
        /// (RFC 4254 section 4 + 7.2). Forwarded from Session when ssh-connection
        /// is already registered. Keepalive is handled at the session level and
        /// never reaches here.
        /// </summary>
        internal void HandleMessage(GlobalRequestMessage message)
        {
            switch (message.RequestName)
            {
                case "tcpip-forward":
                    HandleTcpIpForward(message);
                    break;
                case "cancel-tcpip-forward":
                    HandleCancelTcpIpForward(message);
                    break;
                default:
                    // Unknown global request: reply FAILURE if asked, do not
                    // tear down the session (global requests are advisory).
                    if (message.WantReply)
                        _session.SendMessage(new RequestFailureMessage());
                    break;
            }
        }

        private void HandleTcpIpForward(GlobalRequestMessage message)
        {
            // RFC 4254 section 7.2 payload: string address; uint port.
            string address;
            uint port;
            try
            {
                var reader = new SshDataReader(message.RequestData);
                address = reader.ReadString(Encoding.ASCII);
                port = reader.ReadUInt32();
            }
            catch
            {
                if (message.WantReply)
                    _session.SendMessage(new RequestFailureMessage());
                return;
            }

            // Defer policy/permission to the host; the library only provides
            // the mechanism. Default: accept everything the host permitted by
            // wiring TcpForwardRequestAccepted.
            var args = new TcpForwardRequestArgs(address, (int)port, _auth);
            TcpForwardRequestReceived?.Invoke(this, args);
            if (!args.Accepted)
            {
                Log.Warn($"Reverse forward {address}:{port} rejected by host policy.");
                if (message.WantReply)
                    _session.SendMessage(new RequestFailureMessage());
                return;
            }

            PortForwardingService fwd;
            try
            {
                fwd = new PortForwardingService(address, port, OpenForwardedChannel);
                fwd.Start();
            }
            catch
            {
                Log.Fail($"Reverse forward {address}:{port} failed to start.");
                if (message.WantReply)
                    _session.SendMessage(new RequestFailureMessage());
                return;
            }

            Log.Info($"Reverse forward bound at {fwd.BoundAddress}:{fwd.BoundPort}.");
            lock (_locker)
                _forwarders[(fwd.BoundAddress, fwd.BoundPort)] = fwd;

            if (message.WantReply)
            {
                // RFC 4254 section 4: when the peer requested port 0, include
                // the OS-assigned bound port in the SUCCESS payload; otherwise
                // SUCCESS carries no payload.
                if (port == 0)
                {
                    var success = new RequestSuccessMessageWithPort(fwd.BoundPort);
                    _session.SendMessage(success);
                }
                else
                {
                    _session.SendMessage(new RequestSuccessMessage());
                }
            }
        }

        private void HandleCancelTcpIpForward(GlobalRequestMessage message)
        {
            // RFC 4254 section 7.2 payload: string address; uint port.
            string address;
            uint port;
            try
            {
                var reader = new SshDataReader(message.RequestData);
                address = reader.ReadString(Encoding.ASCII);
                port = reader.ReadUInt32();
            }
            catch
            {
                if (message.WantReply)
                    _session.SendMessage(new RequestFailureMessage());
                return;
            }

            PortForwardingService fwd;
            lock (_locker)
            {
                if (!_forwarders.TryGetValue((address, port), out fwd))
                {
                    // Address may have been normalized by the listener (e.g. Any).
                    // Fall back to a single-match by port alone.
                    fwd = _forwarders.Values.FirstOrDefault(f => f.BoundPort == port);
                    if (fwd != null)
                        _forwarders.Remove((fwd.BoundAddress, fwd.BoundPort));
                }
                else
                {
                    _forwarders.Remove((address, port));
                }
            }

            if (fwd == null)
            {
                Log.Warn($"Cancel reverse forward {address}:{port} not found.");
                if (message.WantReply)
                    _session.SendMessage(new RequestFailureMessage());
                return;
            }

            Log.Debug($"Cancel reverse forward {address}:{port}.");
            try { fwd.Dispose(); } catch { }

            if (message.WantReply)
                _session.SendMessage(new RequestSuccessMessage());
        }

        /// <summary>
        /// Factory called by PortForwardingService for each inbound TCP connection.
        /// Sends SSH_MSG_CHANNEL_OPEN "forwarded-tcpip" to the peer, returns the
        /// pending channel handle. Returns null if the peer rejects the open.
        /// </summary>
        private Channel OpenForwardedChannel(string boundAddress, uint boundPort,
            string originatorIP, uint originatorPort)
        {
            var serverChannelId = (uint)Interlocked.Increment(ref _serverChannelCounter);

            var channel = new PendingForwardedChannel(this, serverChannelId);
            lock (_locker)
                _channels[serverChannelId] = channel;

            var open = new ForwardedTcpIpOpenMessage(
                serverChannelId,
                Session.InitialLocalWindowSize,
                Session.LocalChannelDataPacketSize,
                boundAddress, boundPort,
                originatorIP, originatorPort);
            _session.SendMessage(open);

            return channel;
        }

        /// <summary>
        /// Resolve a server-initiated forwarded channel after the peer's
        /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION arrives. Flushes buffered SendData.
        /// </summary>
        private void HandleMessage(ChannelOpenConfirmationMessage message)
        {
            // message.RecipientChannel is the server-side id we chose; the peer
            // echoes it back. message.SenderChannel is the peer's new channel id.
            Channel channel;
            lock (_locker)
                _channels.TryGetValue(message.RecipientChannel, out channel);

            if (channel is PendingForwardedChannel pending)
            {
                pending.OnConfirmed(message.SenderChannel,
                    message.InitialWindowSize, message.MaximumPacketSize);
                return;
            }

            // Confirmation for a channel we did not initiate: protocol error,
            // but safer to ignore than to tear down the session.
        }

        /// <summary>
        /// Peer rejected our server-initiated forwarded-tcpip open. Tear down
        /// the pending channel; the associated TCP socket (managed by
        /// PortForwardingService) will be closed separately.
        /// </summary>
        private void HandleMessage(ChannelOpenFailureMessage message)
        {
            Channel channel;
            lock (_locker)
                _channels.TryGetValue(message.RecipientChannel, out channel);

            if (channel is PendingForwardedChannel pending)
            {
                lock (_locker)
                    _channels.Remove(pending.ServerChannelId);
                // Pending channel never registered with a bridge, so just drop.
            }
        }

        /// <summary>Wrap a SUCCESS reply that carries a uint port payload (RFC 4254 section 4).</summary>
        private sealed class RequestSuccessMessageWithPort : Message
        {
            private readonly uint _port;
            public RequestSuccessMessageWithPort(uint port) { _port = port; }
            public override byte MessageType => 81;
            protected override void OnGetPacket(SshDataWriter writer)
                => writer.Write(_port);
        }

        /// <summary>Server-initiated forwarded-tcpip channel awaiting confirmation.</summary>
        private sealed class PendingForwardedChannel : Channel
        {
            public PendingForwardedChannel(ConnectionService svc, uint serverChannelId)
                : base(svc, 0, 0, 0, serverChannelId) { }
        }

        private void HandleMessage(DirectTcpIpMessage message)
        {
            Log.Info($"Direct TCP forward requested: {message.Host}:{message.Port}.");
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
                case "keepalive@openssh.com":
                    // OpenSSH liveness probe sent on a specific channel rather
                    // than via SSH_MSG_GLOBAL_REQUEST. No payload; just prove
                    // we are alive when the peer asks for a reply. Do NOT fall
                    // through to default - that would throw and tear down the
                    // session, defeating the probe.
                    if (message.WantReply)
                    {
                        var channelKeepAlive = FindChannelByServerId<Channel>(message.RecipientChannel);
                        _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channelKeepAlive.ClientChannelId });
                    }
                    break;
                default:
                    Log.Warn($"Unknown channel request: {message.RequestType}.");
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
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Channel data: server-id={message.RecipientChannel} bytes={message.Data.Length}");
            var channel = FindChannelByServerId<Channel>(message.RecipientChannel);
            channel.OnData(message.Data);
        }

        private void HandleMessage(ChannelWindowAdjustMessage message)
        {
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Window adjust: channel={message.RecipientChannel} delta={message.BytesToAdd}");
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

            Log.Info($"Channel opened: type={message.ChannelType} client-id={message.SenderChannel} server-id={channel.ServerChannelId}.");

            lock (_locker)
                _channels[channel.ServerChannelId] = channel;

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

            Log.Info($"Shell requested on channel {channel.ServerChannelId}.");
            var args = new CommandRequestedArgs(channel, "shell", null, _auth);
            CommandOpened?.Invoke(this, args);

            if (message.WantReply)
                if (args.Agreed)
                    _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
                else
                    _session.SendMessage(new ChannelFailureMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(CommandRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            Log.Info($"Exec requested on channel {channel.ServerChannelId}: \"{message.Command}\".");
            var args = new CommandRequestedArgs(channel, "exec", message.Command, _auth);
            CommandOpened?.Invoke(this, args);

            if (message.WantReply)
                if (args.Agreed)
                    _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
                else
                    _session.SendMessage(new ChannelFailureMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(SubsystemRequestMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            Log.Info($"Subsystem requested on channel {channel.ServerChannelId}: {message.Name}.");

            // Backward-compatible generic event (ShellType == "subsystem").
            var args = new CommandRequestedArgs(channel, "subsystem", message.Name, _auth);
            CommandOpened?.Invoke(this, args);

            // Dedicated subsystem event (RFC 4254 section 6.5). When the host
            // subscribes to it, its Agreed flag wins; otherwise the legacy
            // CommandOpened decision applies. Exactly one reply is sent below.
            var subsystemArgs = new SubsystemRequestedArgs(channel, message.Name, _auth);
            if (SubsystemRequested != null)
            {
                SubsystemRequested.Invoke(this, subsystemArgs);
                args.Agreed = subsystemArgs.Agreed;
            }

            if (message.WantReply)
                if (args.Agreed)
                    _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
                else
                    _session.SendMessage(new ChannelFailureMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(WindowChangeMessage message)
        {
            var channel = FindChannelByServerId<SessionChannel>(message.RecipientChannel);

            channel.OnWindowChange(new WindowChangeArgs(channel, message.WidthColumns, message.HeightRows, message.WidthPixels, message.HeightPixels));
        }

        private T FindChannelByServerId<T>(uint id) where T : Channel
        {
            lock (_locker)
            {
                var channel = _channels.TryGetValue(id, out var c) ? c as T : null;
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
                _channels.Remove(channel.ServerChannelId);
            }
        }
    }
}
