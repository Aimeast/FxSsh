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
    /// <summary>
    /// Implements the "ssh-connection" service (RFC 4254): opens and
    /// multiplexes channels, dispatches channel data, window adjust, EOF and
    /// close messages, and handles channel requests such as "pty-req", "env",
    /// "shell", "exec" and "subsystem" plus global requests for reverse
    /// TCP/IP port forwarding (RFC 4254 section 7).
    /// </summary>
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

        // Bounded: a peer flooding channel messages must not be able to grow
        // the server-side queue without limit. When the queue is full the
        // session is disconnected (the message loop cannot keep up).
        private readonly System.Threading.Channels.Channel<ConnectionServiceMessage> _messageChannel;
        private readonly CancellationTokenSource _messageCts = new();

        private int _serverChannelCounter = -1;

        // Reverse port forwarding: one listener per (address, port) the peer
        // requested via "tcpip-forward". Keyed by (address, port) using the
        // bound endpoint the listener actually used (so cancel-tcpip-forward
        // matches against the bound port the peer learned from our SUCCESS).
        private readonly Dictionary<(string address, uint port), PortForwardingService> _forwarders = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="ConnectionService"/>
        /// class and starts its asynchronous channel-message loop.
        /// </summary>
        /// <param name="session">The session that instantiated the service after successful user authentication.</param>
        /// <param name="auth">The authentication result accepted by <see cref="UserAuthService.UserAuth"/>; attached to event args so handlers can apply per-user policy.</param>
        public ConnectionService(Session session, UserAuthArgs auth)
            : base(session)
        {
            ArgumentNullException.ThrowIfNull(auth);

            _auth = auth;
            _messageChannel = System.Threading.Channels.Channel.CreateBounded<ConnectionServiceMessage>(
                new BoundedChannelOptions(session.Limits.MaximumQueuedChannelMessages)
                {
                    SingleReader = true,
                    SingleWriter = true,
                });

            Task.Run(MessageLoopAsync);
        }

        /// <summary>
        /// Occurs when the client requests a shell ("shell") or a command
        /// execution ("exec") on a session channel. For backward
        /// compatibility it is also raised for "subsystem" requests (with
        /// <see cref="CommandRequestedArgs.ShellType"/> "subsystem") - prefer
        /// <see cref="SubsystemRequested"/> there. Set
        /// <see cref="CommandRequestedArgs.Agreed"/> to true to accept;
        /// otherwise SSH_MSG_CHANNEL_FAILURE is sent when the client asked for
        /// a reply.
        /// </summary>
        public event EventHandler<CommandRequestedArgs> CommandOpened;
        /// <summary>
        /// Occurs when the client requests a subsystem (RFC 4254 section 6.5,
        /// e.g. "sftp"). When handled, <see cref="SubsystemRequestedArgs.Agreed"/>
        /// overrides the legacy <see cref="CommandOpened"/> decision for this
        /// request.
        /// </summary>
        public event EventHandler<SubsystemRequestedArgs> SubsystemRequested;
        /// <summary>Occurs when the client sets an environment variable with an "env" channel request (RFC 4254 section 6.4).</summary>
        public event EventHandler<EnvironmentArgs> EnvReceived;
        /// <summary>Occurs when the client requests a pseudo-terminal with a "pty-req" channel request (RFC 4254 section 6.2).</summary>
        public event EventHandler<PtyArgs> PtyReceived;
        /// <summary>
        /// Occurs when the client opens a TCP forwarding channel: "direct-tcpip"
        /// for client-initiated forwarding, or "forwarded-tcpip" when a
        /// connection arrives on a reverse-forwarded listener. The channel is
        /// already confirmed at this point, so the event is informational
        /// (target host, port and originator); no accept/reject decision is
        /// sent back to the peer.
        /// </summary>
        public event EventHandler<TcpRequestArgs> TcpForwardRequest;

        /// <summary>
        /// Raised when the peer requests a reverse port forwarding listener
        /// via SSH_MSG_GLOBAL_REQUEST "tcpip-forward". The host MUST set
        /// args.Accepted = true to permit the listener; default false rejects.
        /// </summary>
        public event EventHandler<TcpForwardRequestArgs> TcpForwardRequestReceived;

        /// <summary>
        /// Stops the message loop, force-closes every open channel and
        /// disposes every reverse-forward listener, since their TCP sockets
        /// must not outlive the session.
        /// </summary>
        protected internal override void CloseService()
        {
            _messageCts.Cancel();
            _messageChannel.Writer.TryComplete();

            // Release pooled channel-data buffers still sitting in the queue
            // (the message loop may already have exited on cancellation).
            while (_messageChannel.Reader.TryRead(out var pending))
                (pending as ChannelDataMessage)?.DataLease?.ReleaseIfNotRetained();

            lock (_locker)
            {
                foreach (var channel in _channels.Values.ToArray())
                {
                    // One failing channel teardown must not abort the close of
                    // the remaining channels or the reverse-forward listeners.
                    try { channel.ForceClose(); }
                    catch (Exception ex) { Log.Warn($"Force-closing a channel during session teardown failed: {ex.Message}"); }
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
                Dispatch(message);
            else
            {
                // The queued message's RawBytes is a zero-copy slice over the
                // SSH receive buffer, which is recycled by the next
                // ReceiveMessage. The queue is drained asynchronously, so any
                // message that will be re-parsed with LoadFrom<T> must keep an
                // independent copy. Only ChannelOpenMessage and
                // ChannelRequestMessage are re-parsed later (into a concrete
                // subtype); every other message materialises its fields in
                // OnLoad before it is queued and never touches RawBytes again.
                if (message is ChannelOpenMessage || message is ChannelRequestMessage)
                    message.SnapshotRawBytes();

                // Channel data is copied once into a pooled lease: the public
                // DataReceived callback sees a transient view, and the
                // in-library forwarding/SFTP consumers can take ownership
                // instead of copying again. The message loop releases the
                // lease after dispatch when nobody retained it.
                if (message is ChannelDataMessage data)
                {
                    data.DataLease = ChannelDataLease.CopyFrom(data.Data);
                    data.Data = data.DataLease.Memory;
                }
                if (!_messageChannel.Writer.TryWrite(message))
                {
                    (message as ChannelDataMessage)?.DataLease?.ReleaseIfNotRetained();
                    Log.Fail("Connection service message queue is full; disconnecting.");
                    _session.Disconnect(DisconnectReason.ByApplication, "Too many queued channel messages.");
                }
            }
        }

        private async Task MessageLoopAsync()
        {
            try
            {
                await foreach (var message in _messageChannel.Reader.ReadAllAsync(_messageCts.Token))
                {
                    var lease = (message as ChannelDataMessage)?.DataLease;
                    try
                    {
                        Dispatch(message);
                    }
                    catch (SshConnectionException ex)
                    {
                        // A channel-level protocol violation is fatal for the
                        // connection; log and tear the session down instead of
                        // silently dropping the message.
                        Log.Fail($"Connection service protocol error: {ex.Message}");
                        _session.Disconnect(ex.DisconnectReason, ex.Message);
                        return;
                    }
                    catch (Exception ex)
                    {
                        // A single malformed/hostile message must not kill the
                        // whole channel-processing loop silently.
                        Log.Fail($"Connection service message handling failed: {ex}");
                    }
                    finally
                    {
                        lease?.ReleaseIfNotRetained();
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        }

        /// <summary>
        /// Compile-time dispatch replacing the former (dynamic) binder.
        /// Concrete ChannelOpenMessage / ChannelRequestMessage subclasses are
        /// matched before their bases, mirroring the old most-specific-overload
        /// dynamic binding (e.g. EnvMessage reaches its own handler rather
        /// than the ChannelRequestMessage base).
        /// </summary>
        private void Dispatch(ConnectionServiceMessage message)
        {
            switch (message)
            {
                case ForwardedTcpIpMessage m: HandleMessage(m); break;
                case DirectTcpIpMessage m: HandleMessage(m); break;
                case SessionOpenMessage m: HandleMessage(m); break;
                case ChannelOpenMessage m: HandleMessage(m); break;
                case EnvMessage m: HandleMessage(m); break;
                case PtyRequestMessage m: HandleMessage(m); break;
                case WindowChangeMessage m: HandleMessage(m); break;
                case ShellRequestMessage m: HandleMessage(m); break;
                case CommandRequestMessage m: HandleMessage(m); break;
                case SubsystemRequestMessage m: HandleMessage(m); break;
                case ChannelRequestMessage m: HandleMessage(m); break;
                case ShouldIgnoreMessage m: HandleMessage(m); break;
                case GlobalRequestMessage m: HandleMessage(m); break;
                case ChannelOpenConfirmationMessage m: HandleMessage(m); break;
                case ChannelOpenFailureMessage m: HandleMessage(m); break;
                case ChannelDataMessage m: HandleMessage(m); break;
                case ChannelWindowAdjustMessage m: HandleMessage(m); break;
                case ChannelEofMessage m: HandleMessage(m); break;
                case ChannelCloseMessage m: HandleMessage(m); break;
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
                    // RFC 4254 section 5.1: refuse the open and keep the
                    // connection alive; an unknown channel type is not a
                    // transport-level error.
                    _session.SendMessage(new ChannelOpenFailureMessage
                    {
                        RecipientChannel = message.SenderChannel,
                        ReasonCode = ChannelOpenFailureReason.UnknownChannelType,
                        Description = string.Format("Unknown channel type: {0}.", message.ChannelType),
                    });
                    break;
            }
        }

        private void HandleMessage(ShouldIgnoreMessage message)
        {
        }

        private void HandleMessage(ForwardedTcpIpMessage message)
        {
            var channel = HandleChannelOpenMessage(message);
            if (channel == null)
                return;
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
            // RFC 4254 section 7.1 payload: string address; uint port.
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
            // RFC 4254 section 7.1 payload: string address; uint port.
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
                    // Fall back by port alone, but only when exactly one
                    // listener matches: with several listeners on the same
                    // port across addresses, guessing would tear down the
                    // wrong one.
                    var matches = _forwarders
                        .Where(kv => kv.Value.BoundPort == port)
                        .Take(2)
                        .ToArray();
                    if (matches.Length == 1)
                    {
                        fwd = matches[0].Value;
                        _forwarders.Remove(matches[0].Key);
                    }
                    else
                    {
                        fwd = null;
                    }
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
            {
                if (_channels.Count >= _session.Limits.MaximumChannels)
                {
                    Log.Warn($"Refusing forwarded channel: {_session.Limits.MaximumChannels} channels already open.");
                    // The caller closes the accepted TCP socket when the
                    // factory returns null.
                    return null;
                }
                _channels[serverChannelId] = channel;
            }

            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Forwarded channel {serverChannelId} opened to peer, awaiting confirmation.");

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

            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Channel open confirmation: rchan={message.RecipientChannel} sender={message.SenderChannel} found={(channel != null)} pending={channel is PendingForwardedChannel} hash={channel?.GetHashCode()}.");

            if (channel is PendingForwardedChannel pending)
            {
                if (message.MaximumPacketSize == 0)
                {
                    Log.Warn($"Peer confirmed forwarded channel {message.RecipientChannel} with a zero maximum packet size; closing it.");
                    lock (_locker)
                        _channels.Remove(pending.ServerChannelId);
                    pending.ForceClose();
                    return;
                }

                pending.OnConfirmed(message.SenderChannel,
                    message.InitialWindowSize, message.MaximumPacketSize);
                return;
            }

            // Confirmation for a channel we did not initiate: protocol error,
            // but safer to ignore than to tear down the session.
        }

        /// <summary>
        /// Peer rejected our server-initiated forwarded-tcpip open. Force the
        /// pending channel closed so anything bridged to it (the forwarded
        /// TCP socket) is torn down instead of lingering forever.
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
                pending.ForceClose();
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
            // The 2-parameter protected ctor marks the channel as pending
            // (buffering outbound data until OPEN_CONFIRMATION resolves the
            // peer window); the 5-parameter public ctor would leave the peer
            // window at zero and stall every send forever.
            public PendingForwardedChannel(ConnectionService svc, uint serverChannelId)
                : base(svc, serverChannelId) { }
        }

        private void HandleMessage(DirectTcpIpMessage message)
        {
            Log.Info($"Direct TCP forward requested: {message.Host}:{message.Port}.");
            var channel = HandleChannelOpenMessage(message);
            if (channel == null)
                return;
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
                    if (message.WantReply
                        && TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var simpleChannel))
                    {
                        _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = simpleChannel.ClientChannelId });
                    }
                    break;
                case "winadj@putty.projects.tartarus.org":
                    //https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html
                    if (TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var winAdjChannel))
                        _session.SendMessage(new ChannelFailureMessage { RecipientChannel = winAdjChannel.ClientChannelId });
                    break;
                case "auth-agent-req@openssh.com":
                    // https://github.com/openssh/openssh-portable/blob/V_8_0_P1/session.c#L2225
                    break;
                case "keepalive@openssh.com":
                    // OpenSSH liveness probe sent on a specific channel rather
                    // than via SSH_MSG_GLOBAL_REQUEST. No payload; just prove
                    // we are alive when the peer asks for a reply. A probe
                    // racing a channel close is ignored instead of being
                    // treated as a protocol violation.
                    if (message.WantReply
                        && TryFindChannelByServerId<Channel>(message.RecipientChannel, out var keepAliveChannel))
                    {
                        _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = keepAliveChannel.ClientChannelId });
                    }
                    break;
                default:
                    Log.Warn($"Unknown channel request: {message.RequestType}.");
                    // Unknown channel requests are advisory; answer FAILURE
                    // when a reply was requested and keep the connection. A
                    // request for a channel that just closed is ignored: there
                    // is no client channel id left to address a reply to.
                    if (message.WantReply
                        && TryFindChannelByServerId<Channel>(message.RecipientChannel, out var requestChannel))
                    {
                        _session.SendMessage(new ChannelFailureMessage
                        {
                            RecipientChannel = requestChannel.ClientChannelId
                        });
                    }
                    break;
            }
        }

        private void HandleMessage(EnvMessage message)
        {
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

            EnvReceived?.Invoke(this, new EnvironmentArgs(channel, message.Name, message.Value, _auth));

            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
        }

        private void HandleMessage(PtyRequestMessage message)
        {
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

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

            // RFC 4254 has no error for data on a channel the peer never
            // opened (it may race a close). Ignore it, as OpenSSH does,
            // instead of treating it as a transport-level violation.
            var channel = FindChannelByServerIdOrNull<Channel>(message.RecipientChannel);
            if (channel == null)
            {
                Log.Debug($"Channel data for unknown server channel {message.RecipientChannel}; ignored.");
                return;
            }
            channel.OnData(message.DataLease ?? ChannelDataLease.Wrap(message.Data));
        }

        private void HandleMessage(ChannelWindowAdjustMessage message)
        {
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Window adjust: channel={message.RecipientChannel} delta={message.BytesToAdd}");
            var channel = FindChannelByServerIdOrNull<Channel>(message.RecipientChannel);
            if (channel == null)
            {
                Log.Debug($"Window adjust for unknown server channel {message.RecipientChannel}; ignored.");
                return;
            }
            channel.ClientAdjustWindow(message.BytesToAdd);
        }

        private void HandleMessage(ChannelEofMessage message)
        {
            var channel = FindChannelByServerIdOrNull<Channel>(message.RecipientChannel);
            if (channel == null)
            {
                Log.Debug($"EOF for unknown server channel {message.RecipientChannel}; ignored.");
                return;
            }
            channel.OnEof();
        }

        private void HandleMessage(ChannelCloseMessage message)
        {
            var channel = FindChannelByServerIdOrNull<Channel>(message.RecipientChannel);
            if (channel == null)
            {
                Log.Debug($"Close for unknown server channel {message.RecipientChannel}; ignored.");
                return;
            }
            channel.OnClose();
        }

        private void HandleMessage(SessionOpenMessage message)
        {
            HandleChannelOpenMessage(message);
        }

        private SessionChannel HandleChannelOpenMessage(ChannelOpenMessage message)
        {
            // RFC 4254 section 5.1: a zero maximum packet size cannot carry
            // any payload; reject it up front instead of stalling all sends.
            if (message.MaximumPacketSize == 0)
            {
                SendOpenFailure(message.SenderChannel, ChannelOpenFailureReason.AdministrativelyProhibited,
                    "Maximum packet size must be greater than zero.");
                return null;
            }

            SessionChannel channel;
            lock (_locker)
            {
                if (_channels.Count >= _session.Limits.MaximumChannels)
                {
                    channel = null;
                }
                else
                {
                    channel = new SessionChannel(
                        this,
                        message.SenderChannel,
                        message.InitialWindowSize,
                        message.MaximumPacketSize,
                        (uint)Interlocked.Increment(ref _serverChannelCounter));
                    _channels[channel.ServerChannelId] = channel;
                }
            }

            if (channel == null)
            {
                Log.Warn($"Refusing channel open ({message.ChannelType}): {_session.Limits.MaximumChannels} channels already open.");
                SendOpenFailure(message.SenderChannel, ChannelOpenFailureReason.ResourceShortage,
                    "Too many open channels.");
                return null;
            }

            Log.Info($"Channel opened: type={message.ChannelType} client-id={message.SenderChannel} server-id={channel.ServerChannelId}.");

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

        private void SendOpenFailure(uint senderChannel, ChannelOpenFailureReason reason, string description)
        {
            _session.SendMessage(new ChannelOpenFailureMessage
            {
                RecipientChannel = senderChannel,
                ReasonCode = reason,
                Description = description,
            });
        }

        private void HandleMessage(ShellRequestMessage message)
        {
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

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
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

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
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

            Log.Info($"Subsystem requested on channel {channel.ServerChannelId}: {message.Name}.");

            // Backward-compatible generic event (ShellType == "subsystem"):
            // hosts that predate SubsystemRequested decide here.
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
            if (!TryFindChannelByServerId<SessionChannel>(message.RecipientChannel, out var channel))
                return;

            channel.OnWindowChange(new WindowChangeArgs(channel, message.WidthColumns, message.HeightRows, message.WidthPixels, message.HeightPixels));

            // window-change normally sets want_reply=false, but RFC 4254
            // section 6.7 allows a client to request an acknowledgement.
            if (message.WantReply)
                _session.SendMessage(new ChannelSuccessMessage { RecipientChannel = channel.ClientChannelId });
        }

        /// <summary>
        /// Look up an open channel of the requested type. Returns false for an
        /// unknown id or a channel of another type: every channel message can
        /// race a close, so callers drop or answer the message instead of
        /// treating it as a transport-level violation.
        /// </summary>
        private bool TryFindChannelByServerId<T>(uint id, out T channel) where T : Channel
        {
            lock (_locker)
            {
                if (_channels.TryGetValue(id, out var c) && c is T typed)
                {
                    channel = typed;
                    return true;
                }
            }

            channel = null;
            return false;
        }

        /// <summary>
        /// Look up an open channel, returning null for an unknown id. Used by
        /// the data/control hot path, where a message racing a channel close
        /// must be dropped rather than treated as a protocol violation.
        /// </summary>
        private T FindChannelByServerIdOrNull<T>(uint id) where T : Channel
            => TryFindChannelByServerId(id, out T channel) ? channel : null;

        internal void RemoveChannel(Channel channel)
        {
            lock (_locker)
            {
                _channels.Remove(channel.ServerChannelId);
            }
        }
    }
}
