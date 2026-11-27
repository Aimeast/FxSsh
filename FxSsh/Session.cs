using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh.Algorithms;
using FxSsh.Algorithms.Catalog;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Services;

namespace FxSsh
{
    /// <summary>
    /// Represents a single SSH connection accepted by an <see cref="SshServer"/>,
    /// running the transport layer (version exchange, key exchange, and the
    /// binary packet protocol per RFC 4253) and hosting the services
    /// (ssh-userauth, ssh-connection) negotiated over it.
    /// </summary>
    public class Session
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        // Advertised receive window (RFC 4254 section 5.2). 2 MiB matches the
        // OpenSSH default and halves the WINDOW_ADJUST round-trips of the old
        // 1 MiB window (64 vs 32 packets between refreshes), which matters for
        // single-connection throughput and high-concurrency message-loop churn.
        internal const int InitialLocalWindowSize = LocalChannelDataPacketSize * 64;
        internal const int LocalChannelDataPacketSize = 1024 * 32;
        // RFC 4253 section 6.1: all implementations MUST be able to process packets with
        // a total size of 35000 bytes or less; anything larger is rejected to
        internal const int MaximumPacketLength = 35000;
        // RFC 4253 section 6: minimum packet size is 16 bytes total, i.e. packet_length >= 12.
        internal const int MinimumPacketLength = 12;
        // RFC 4253 section 4.2: the identification string is at most 255
        // characters, including the terminating CR LF.
        private const int MaximumVersionLineLength = 255;

        // Active algorithm set for this session; frozen from the server's
        // pluggable AlgorithmSelection in the ctor (see below).
        private readonly FrozenAlgorithmCollection<KexAlgorithm> _keyExchangeAlgorithms;
        internal readonly FrozenAlgorithmCollection<PublicKeyAlgorithm> _publicKeyAlgorithms;
        // Catalog order filtered to the host keys this session actually has;
        // frozen once because both inputs are immutable after construction.
        private readonly string[] _hostKeyAlgorithmNames;
        private readonly FrozenAlgorithmCollection<CipherInfo> _encryptionAlgorithms;
        private readonly FrozenAlgorithmCollection<HmacInfo> _hmacAlgorithms;
        private readonly FrozenAlgorithmCollection<CompressionAlgorithm> _compressionAlgorithms;

        private readonly object _locker = new();
        private Socket _socket;
        private bool _disconnected;
        private TaskCompletionSource _disconnectCompletion;
        private readonly Dictionary<string, string> _hostKey;
        // Host key instances are created from the registered PEM lazily and
        // reused across rekeys. KEX is serialized on the receive pump; the
        // cache is also touched by ReleaseAlgorithms after every pump stops.
        private readonly Dictionary<string, PublicKeyAlgorithm> _hostKeyInstances = [];

        // Async transport core. Raw socket bytes flow in through _receivePipe
        // (filled by FillPipeAsync) and are consumed as framed packets by
        // ProcessPipeAsync; outbound wire buffers are enqueued to _sendChannel
        // by SendMessageInternal and written by the single-reader send pump
        // (ProcessSendChannelAsync). No thread is ever blocked on socket I/O,
        // so thousands of sessions do not consume a thread each - the
        // ConnectionService.MessageLoop and the per-session pumps are all
        // async tasks that park on the pipe/channel instead.
        private readonly Pipe _receivePipe = new();

        // Outbound frames are bounded by one session-wide byte budget that is
        // shared with the per-channel send backlogs (see SessionLimits). A
        // peer that advertises a huge receive window and then stops reading
        // must not be able to grow this queue without limit. Overflow is a
        // fatal condition - the session is torn down rather than silently
        // dropping frames (which would desynchronise the packet stream).
        private readonly System.Threading.Channels.Channel<PooledBuffer> _sendChannel;
        private long _bufferedOutboundBytes;

        // The pooled payload buffer backing the message currently being
        // dispatched. The AEAD and ETM receive paths hand their rental over
        // instead of returning it when ReceiveMessageAsync returns, because
        // ChannelDataMessage.Data and Message.RawBytes are zero-copy slices
        // into it. It is released only after HandleMessageCore has copied the
        // bytes - the pool has a cross-thread shared fallback, so returning
        // earlier would let another thread rent and overwrite the packet.
        private PooledBuffer _dispatchBuffer;

        private CancellationTokenSource _sessionCts;
        private Task _sendPumpTask;

        // OpenSSH strict KEX (Terrapin mitigation, CVE-2023-48795). The
        // marker sent by the client is only meaningful in the initial
        // KEXINIT; once negotiated, unexpected packets during the initial
        // exchange are fatal and packet sequence numbers restart at zero
        // after every NEWKEYS.
        private const string StrictKexClientMarker = "kex-strict-c-v00@openssh.com";
        private const string StrictKexServerMarker = "kex-strict-s-v00@openssh.com";
        private bool _strictKex;
        private bool _initialKexInitReceived;
        private bool _preKexPacketSeen;
        private bool _firstKeyExchangeComplete;

        // Upper bound on messages parked while a key exchange is in flight.
        // The queue holds copies of channel data (up to 32 KiB each), so an
        // unbounded queue would let a peer that keeps sending during rekey
        // exhaust server memory.
        private const int MaximumBlockedMessages = 1024;

        // Server-side keepalive. IdleThreshold is both the idle threshold that
        // starts the probing and the resend cadence once probing has started.
        // Probes are counted; MaxMissedProbes unanswered probes disconnect the
        // session. Both directions of traffic refresh _lastActivity (sending a
        // frame also proves the link is alive and advances the peer's ACK).
        private const int MaxMissedProbes = 3;
        private TimeSpan _keepaliveIdle = TimeSpan.Zero;   // <=0 means disabled
        private Stopwatch _lastActivity;
        private int _missedProbes;
        private long _lastProbeTimestamp;
        private TimeSpan _inactivityTimeout = TimeSpan.Zero;   // <=0 means disabled
        private Timer _lifecycleTimer;

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private bool _versionAccepted;
        private Algorithms _algorithms = null;
        private ExchangeContext _exchangeContext = null;
        private List<SshService> _services = [];

        // Protocol extensions (RFC 8308)
        private Dictionary<string, string> _extensionsToSend = [];
        private bool _clientAdvertisedExtInfo;  // client KEXINIT had "ext-info-c"
        // All access is under _locker; a plain queue avoids the unnecessary
        // concurrent-collection overhead.
        private readonly Queue<Message> _blockedMessages = new();
        private bool _discardNextKexPacket;

        private static long _nextId = 0;

        /// <summary>
        /// Gets the unique identifier of this session, assigned when the
        /// session is constructed. Values increase monotonically per process.
        /// </summary>
        public long Id { get; }

        /// <summary>
        /// Gets the immutable limits snapshot this session was constructed
        /// with. Replacing <see cref="SshServer.Limits"/> later does not
        /// affect an existing session.
        /// </summary>
        public SessionLimits Limits { get; }

        /// <summary>
        /// Gets the server protocol version banner (e.g. "SSH-2.0-FxSsh") sent
        /// to the client during the version exchange.
        /// </summary>
        public string ServerVersion { get; private set; }

        /// <summary>
        /// Gets the client protocol version string (e.g. "SSH-2.0-OpenSSH_9.6")
        /// received during the version exchange; populated once
        /// <see cref="StartAsync(CancellationToken)"/> has run the handshake.
        /// </summary>
        public string ClientVersion { get; private set; }

        /// <summary>
        /// Gets the session identifier: the exchange hash computed by the
        /// first key exchange (RFC 4253 section 7.2). Null until the first key
        /// exchange completes; it never changes across subsequent rekeys.
        /// </summary>
        public byte[] SessionId { get; private set; }

        /// <summary>
        /// Gets the client's address and port, captured from the accepted
        /// socket when the session is constructed, so it stays available
        /// after the session disconnects.
        /// </summary>
        public EndPoint RemoteEndPoint { get; }

        /// <summary>
        /// Gets the registered service instance of type
        /// <typeparamref name="T"/>, or null when no such service has been
        /// registered for this session yet.
        /// </summary>
        /// <typeparam name="T">The service type to look up.</typeparam>
        public T GetService<T>() where T : SshService
        {
            return (T)_services.FirstOrDefault(x => x is T);
        }

        /// <summary>
        /// Creates a session over an accepted socket. The algorithm selection
        /// is frozen at construction (a null <paramref name="algorithms"/>
        /// uses the library defaults); later ConfigureHazmat calls on the
        /// same selection throw.
        /// </summary>
        public Session(Socket socket, Dictionary<string, string> hostKey, string serverBanner,
            AlgorithmSelection algorithms = null, SessionLimits limits = null)
        {
            ArgumentNullException.ThrowIfNull(socket);
            ArgumentNullException.ThrowIfNull(hostKey);

            Limits = limits ?? new SessionLimits();
            Limits.Validate();
            _sendChannel = System.Threading.Channels.Channel.CreateUnbounded<PooledBuffer>(
                new UnboundedChannelOptions { SingleReader = true });

            // The banner is written verbatim into the version-exchange line:
            // reject anything longer than the RFC limit or carrying an
            // embedded CR/LF (which would inject extra protocol lines).
            if (string.IsNullOrEmpty(serverBanner)
                || serverBanner.Length + 2 > MaximumVersionLineLength
                || serverBanner.Contains('\r') || serverBanner.Contains('\n'))
                throw new ArgumentException(
                    string.Format("Server banner must be 1-{0} characters and must not contain CR or LF.", MaximumVersionLineLength - 2),
                    nameof(serverBanner));

            Id = Interlocked.Increment(ref _nextId);
            _socket = socket;
            RemoteEndPoint = socket.RemoteEndPoint;
            _hostKey = hostKey.ToDictionary(s => s.Key, s => s.Value);
            ServerVersion = serverBanner;

            // The server's algorithm catalog (mutable only via
            // SshServer.Algorithms.ConfigureHazmat before the server starts)
            // is the source of truth for every category. The per-session
            // selections are a snapshot frozen right here - BuildSelection is
            // idempotent, so SshServer.Start's earlier freeze is reused - so
            // every construction path ends up with a valid immutable
            // snapshot, and later ConfigureHazmat calls on the same
            // selection throw.
            algorithms ??= new AlgorithmSelection();
            algorithms.BuildSelection(null);
            _publicKeyAlgorithms = algorithms.HostKeySelection;
            _keyExchangeAlgorithms = algorithms.KeyExchangeSelection;
            _encryptionAlgorithms = algorithms.EncryptionSelection;
            _hmacAlgorithms = algorithms.HmacSelection;
            _compressionAlgorithms = algorithms.CompressionSelection;
            _hostKeyAlgorithmNames = _publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray();

            // RFC 8332: advertise which signature algorithms we accept for
            // publickey auth. OpenSSH 8.8+ refuses to sign unless the server
            // sends server-sig-algs (it assumes legacy ssh-rsa otherwise),
            // and we advertise "ext-info-s" in KEXINIT, so this must be sent.
            RegisterExtension("server-sig-algs", string.Join(",", _publicKeyAlgorithms.Keys));
        }

        /// <summary>
        /// Occurs when the session has been disconnected and its socket
        /// closed, whether by application request, protocol error, or peer
        /// disconnect.
        /// </summary>
        public event EventHandler<EventArgs> Disconnected;

        /// <summary>
        /// Occurs when an SSH service (for example ssh-userauth or
        /// ssh-connection) is registered for this session in response to a
        /// service request from the client.
        /// </summary>
        public event EventHandler<SshService> ServiceRegistered;

        /// <summary>
        /// Occurs when the client's SSH_MSG_KEXINIT is received. The event
        /// arguments expose the algorithm name-lists the client advertised,
        /// for inspection or logging; negotiation itself is performed by the
        /// library.
        /// </summary>
        public event EventHandler<KeyExchangeArgs> KeysExchanged;

        /// <summary>
        /// Run the SSH session to completion (protocol exchange, key exchange,
        /// and the service message loop) without ever blocking a thread on
        /// socket I/O. The session pumps the socket into a receive pipe and
        /// out of a send channel; returns when the peer disconnects, an error
        /// occurs, or the session is torn down.
        /// </summary>
        /// <param name="externalToken">Cancel to tear the session down. Optional.</param>
        public async Task StartAsync(CancellationToken externalToken = default)
        {
            if (!_socket.Connected)
            {
                // The socket died before the session started. Run the normal
                // teardown so services are closed and Disconnected fires
                // instead of leaving a half-constructed session behind.
                await DisconnectAsync(DisconnectReason.ConnectionLost, "Socket is not connected.").ConfigureAwait(false);
                return;
            }

            _sessionCts = new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionCts.Token, externalToken);

            try
            {
                SetSocketOptions();

                var fillPipeTask = FillPipeAsync(linkedCts.Token);
                _sendPumpTask = ProcessSendChannelAsync(linkedCts.Token);
                var processPipeTask = ProcessPipeAsync(linkedCts.Token);

                await Task.WhenAll(fillPipeTask, processPipeTask, _sendPumpTask).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await DisconnectAsync(DisconnectReason.ByApplication, "Session cancelled.").ConfigureAwait(false);
            }
            catch (SshConnectionException ex)
            {
                await DisconnectAsync(ex.DisconnectReason, ex.Message).ConfigureAwait(false);
                // A lost connection is a normal session end; protocol errors
                // are surfaced so SshServer can raise ExceptionRaised.
                if (ex.DisconnectReason != DisconnectReason.ConnectionLost)
                    throw;
            }
            catch (Exception)
            {
                // Never send internal exception text to the peer; the host
                // still receives the original exception through the rethrow.
                await DisconnectAsync(DisconnectReason.ProtocolError, "Internal server error.").ConfigureAwait(false);
                throw;
            }
            finally
            {
                // Every protocol pump has stopped: no KEX handler or sender
                // can still be using the negotiated cipher/MAC state. Release
                // its native handles deterministically here instead of in
                // teardown, which can race an in-flight key exchange.
                ReleaseAlgorithms();
            }
        }

        /// <summary>
        /// Disconnects the session: sends SSH_MSG_DISCONNECT to the peer (when
        /// the transport is still usable), flushes queued outbound frames,
        /// cancels the protocol pumps, shuts the socket down, and raises
        /// <see cref="Disconnected"/>. The first call performs the teardown;
        /// concurrent callers wait for it to finish.
        /// </summary>
        /// <param name="reason">The disconnect reason code reported to the peer.</param>
        /// <param name="description">A human-readable disconnect description.</param>
        /// <remarks>
        /// When <paramref name="reason"/> is not
        /// <see cref="DisconnectReason.ConnectionLost"/>, an
        /// SSH_MSG_DISCONNECT message carrying <paramref name="description"/>
        /// is sent to the peer before the socket is shut down.
        /// </remarks>
        public Task DisconnectAsync(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            lock (_locker)
            {
                // Later callers get the first call's teardown task, so awaiting
                // any DisconnectAsync means the socket is closed and
                // Disconnected has fired.
                if (_disconnected)
                    return _disconnectCompletion?.Task ?? Task.CompletedTask;

                _disconnected = true;
                _disconnectCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }

            return DisconnectCoreAsync(reason, description);
        }

        private async Task DisconnectCoreAsync(DisconnectReason reason, string description)
        {
            try
            {
                await TearDownAsync(reason, description);
            }
            finally
            {
                _disconnectCompletion.TrySetResult();
            }
        }

        private async Task TearDownAsync(DisconnectReason reason, string description)
        {
            _lifecycleTimer?.Dispose();
            _lifecycleTimer = null;

            if (reason != DisconnectReason.ConnectionLost && _versionAccepted)
            {
                // Give the peer a protocol-level reason even when the
                // disconnect is server-initiated (idle timeout, protocol
                // error, application shutdown). RFC 4253 section 11.1.
                // Before the version exchange (e.g. a rejected banner) the
                // peer is not yet speaking binary packets, so there is
                // nothing meaningful to send.
                TrySendMessage(new DisconnectMessage(reason, description));
            }

            // Stop accepting new frames, then give the send pump a bounded
            // window to flush everything already queued (including the
            // DISCONNECT above). A peer that stopped reading must not be able
            // to stall teardown indefinitely.
            _sendChannel.Writer.TryComplete();
            var pump = _sendPumpTask;
            if (pump != null)
            {
                try
                {
                    await pump.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                }
                catch
                {
                    // The pump faulted or the drain timed out; closing the
                    // socket below is the authoritative cleanup either way.
                }
            }

            if (_sessionCts is { IsCancellationRequested: false })
                await _sessionCts.CancelAsync().ConfigureAwait(false);

            try
            {
                if (_socket is { Connected: true })
                    _socket.Shutdown(SocketShutdown.Both);
            }
            catch { }

            try
            {
                _socket?.Close();
                _socket?.Dispose();
            }
            catch { }
            finally
            {
                _socket = null;
            }

            // Drop anything that never made it onto the wire and return those
            // rentals to the pool instead of leaking them until GC.
            while (_sendChannel.Reader.TryRead(out var dropped))
            {
                ReleaseOutboundBuffer(dropped.Length);
                dropped.Dispose();
            }

            Log.Info($"Session disconnected: {reason} - {description}");
            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Disconnects the session without waiting for the teardown to
        /// complete. See
        /// <see cref="DisconnectAsync(DisconnectReason, string)"/> for the
        /// semantics of the parameters.
        /// </summary>
        /// <param name="reason">The disconnect reason code reported to the peer.</param>
        /// <param name="description">A human-readable disconnect description.</param>
        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            _ = DisconnectAsync(reason, description);
        }

        /// <summary>
        /// Detaches and disposes the active and pending cipher/MAC sets. Must
        /// only run once every protocol pump has stopped, so no key-exchange
        /// handler or message sender can still reference them.
        /// </summary>
        private void ReleaseAlgorithms()
        {
            Algorithms algorithms;
            Algorithms pendingAlgorithms;
            PublicKeyAlgorithm[] hostKeys;
            lock (_locker)
            {
                algorithms = _algorithms;
                _algorithms = null;
                pendingAlgorithms = _exchangeContext?.NewAlgorithms;
                if (_exchangeContext != null)
                    _exchangeContext.NewAlgorithms = null;
                _exchangeContext = null;
                hostKeys = [.. _hostKeyInstances.Values];
                _hostKeyInstances.Clear();
            }
            algorithms?.Dispose();
            pendingAlgorithms?.Dispose();
            foreach (var hostKey in hostKeys)
                hostKey.Dispose();
        }

        #region Socket operations
        private void SetSocketOptions()
        {
            _socket.NoDelay = true;
            _socket.LingerState = new LingerOption(enable: false, seconds: 0);
            // Leave SO_RCVBUF/SO_SNDBUF at the OS default. Setting them
            // explicitly disables receive/send buffer autotuning on Linux and
            // capped the TCP window at 64 KiB, which throttles high-RTT links
            // far below the 2 MiB SSH receive window.
        }

        /// <summary>
        /// Receive pump: copy raw socket bytes into the receive pipe. The only
        /// task in the session that touches the socket for reading, so the
        /// protocol loop and every service never block on inbound I/O.
        /// </summary>
        private async Task FillPipeAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    var memory = _receivePipe.Writer.GetMemory(1024);
                    var socket = _socket;
                    if (socket is null) break; // torn down by DisconnectAsync
                    var bytesRead = await socket.ReceiveAsync(memory, SocketFlags.None, token);
                    if (bytesRead == 0) break;

                    // Raw inbound bytes are the finest-grained liveness signal
                    // (they also cover the pre-handshake version exchange, so
                    // stalled clients are caught before authentication).
                    _lastActivity?.Restart();

                    _receivePipe.Writer.Advance(bytesRead);
                    var result = await _receivePipe.Writer.FlushAsync(token);
                    if (result.IsCompleted) break;
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                // Map transport failures to ConnectionLost so the protocol
                // pump does not report a peer reset as an internal error.
                await _receivePipe.Writer.CompleteAsync(
                    new SshConnectionException("Socket receive operation failed.", DisconnectReason.ConnectionLost, ex));
                return;
            }
            await _receivePipe.Writer.CompleteAsync();
        }

        /// <summary>
        /// Protocol pump: banner -> protocol version -> key exchange -> the
        /// SSH message loop. Reads framed packets out of the receive pipe,
        /// decrypts/verifies them, and dispatches to HandleMessageCore. The
        /// replacement for the old blocking EstablishConnection loop.
        /// </summary>
        private async Task ProcessPipeAsync(CancellationToken token)
        {
            try
            {
                // Server banner is the first outbound frame; enqueue it ahead
                // of the version read (matching the old SocketWriteProtocolVersion
                // ordering).
                var bannerLength = Encoding.ASCII.GetByteCount(ServerVersion) + 2;
                var bannerBuf = SshBuffers.Packets.Rent(bannerLength);
                var versionLength = Encoding.ASCII.GetBytes(ServerVersion, bannerBuf);
                "\r\n"u8.CopyTo(bannerBuf.AsSpan(versionLength));
                _sendChannel.Writer.TryWrite(new PooledBuffer(bannerBuf, bannerLength));

                ClientVersion = await ReadProtocolVersionAsync(token);
                Log.Info($"Client version: {ClientVersion}.");
                if (!IsSupportedClientVersion(ClientVersion))
                {
                    Log.Warn($"Unsupported client SSH version: {ClientVersion}.");
                    throw new SshConnectionException(
                        string.Format("Not supported for client SSH version {0}. This server only supports SSH v2.0.", ClientVersion),
                        DisconnectReason.ProtocolVersionNotSupported);
                }
                _versionAccepted = true;

                Log.Debug("Session established, starting key exchange.");
                ConsiderReExchange(true);

                while (!token.IsCancellationRequested)
                {
                    var message = await ReceiveMessageAsync(token);
                    if (message is null) break;

                    try
                    {
                        // Strict KEX requires the initial SSH_MSG_KEXINIT to be
                        // the first packet: remember whether anything arrived
                        // before it so the marker can be rejected retroactively.
                        if (!_firstKeyExchangeComplete && message is not KeyExchangeInitMessage)
                            _preKexPacketSeen = true;

                        // OpenSSH strict KEX: between the initial KEXINIT and
                        // NEWKEYS only key-exchange packets (and DISCONNECT)
                        // are legal, and a second KEXINIT is out of sequence.
                        // This is what makes Terrapin-style prefix truncation
                        // detectable.
                        var unexpected = !IsInitialKexPacket(message)
                            || message is KeyExchangeInitMessage && _initialKexInitReceived;
                        if (_strictKex && !_firstKeyExchangeComplete && _exchangeContext != null && unexpected)
                        {
                            throw new SshConnectionException(
                                string.Format("strict KEX violation: unexpected message type {0}.", DescribeMessageType(message)),
                                DisconnectReason.ProtocolError);
                        }

                        // RFC 4253 7.1: when the client's first_kex_packet_follows
                        // guess was wrong, the packet it sent right after KEXINIT
                        // must be discarded before normal processing resumes.
                        if (_discardNextKexPacket)
                        {
                            _discardNextKexPacket = false;
                            continue;
                        }

                        if (message is UnknownMessage unknownMessage)
                        {
                            Log.Debug($"Unknown message type {unknownMessage.UnknownMessageType}, replying SSH_MSG_UNIMPLEMENTED.");
                            SendMessage(unknownMessage.MakeUnimplementedMessage());
                        }
                        else
                            HandleMessageCore(message);
                    }
                    finally
                    {
                        // The message may hold zero-copy slices over the pooled
                        // receive buffer; release it only after dispatch.
                        ReleaseDispatchBuffer();
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (SshConnectionException ex)
            {
                await DisconnectAsync(ex.DisconnectReason, ex.Message).ConfigureAwait(false);
                throw;
            }
            catch (Exception)
            {
                await DisconnectAsync(DisconnectReason.ProtocolError, "Internal server error.").ConfigureAwait(false);
                throw;
            }
            finally
            {
                ReleaseDispatchBuffer();
                foreach (var service in _services)
                {
                    try
                    {
                        service.CloseService();
                    }
                    catch (Exception ex)
                    {
                        Log.Warn($"Service {service.GetType().Name} failed to close: {ex.Message}");
                    }
                }
                await _receivePipe.Reader.CompleteAsync();
                // The peer is gone (EOF) or the loop failed; make sure the
                // socket, pumps and timers are torn down before StartAsync
                // returns to the caller.
                await DisconnectAsync(DisconnectReason.ConnectionLost, "Session closed.").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Send pump: the single reader of <see cref="_sendChannel"/>. Each
        /// enqueued wire buffer is written to the socket asynchronously; the
        /// rental is returned to the pool once SendAsync has consumed it.
        /// </summary>
        private async Task ProcessSendChannelAsync(CancellationToken token)
        {
            try
            {
                await foreach (var payload in _sendChannel.Reader.ReadAllAsync(token))
                {
                    using (payload)
                    {
                        try
                        {
                            // DisconnectAsync nulls _socket from another task;
                            // read it once so a buffer still queued at teardown
                            // (typically the DISCONNECT message itself) ends the
                            // pump instead of dereferencing null.
                            var socket = _socket;
                            if (socket is null)
                                break;

                            var memory = new ReadOnlyMemory<byte>(payload.Array, 0, payload.Length);
                            await socket.SendAsync(memory, SocketFlags.None, token);
                        }
                        finally
                        {
                            ReleaseOutboundBuffer(payload.Length);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (_disconnected && ex is ObjectDisposedException or SocketException)
            {
                // The socket was closed by DisconnectAsync while a send was in flight: expected.
            }
            catch (Exception ex)
            {
                throw new SshConnectionException("Socket send operation failed.", DisconnectReason.ConnectionLost, ex);
            }
        }

        private static bool IsInitialKexPacket(Message message)
        {
            if (message is UnknownMessage)
                return false;

            var type = message.MessageType;
            return type == DisconnectMessage.MessageNumber
                || type == KeyExchangeInitMessage.MessageNumber
                || type == NewKeysMessage.MessageNumber
                || (type >= 30 && type <= 49);      // method-specific KEX packets
        }

        private static byte DescribeMessageType(Message message)
            => message is UnknownMessage unknown ? unknown.UnknownMessageType : message.MessageType;

        private void ReleaseDispatchBuffer()
        {
            _dispatchBuffer.Dispose();
            _dispatchBuffer = default;
        }

        /// <summary>
        /// Tears the session down when the bounded outbound queue overflows.
        /// Called while <see cref="_locker"/> is held; <see cref="DisconnectAsync"/>
        /// re-enters that lock safely and the <c>_disconnected</c> flag stops
        /// the DISCONNECT it tries to enqueue from recursing back here.
        /// </summary>
        private void OnOutboundQueueOverflow(string description)
        {
            if (!_disconnected)
                _ = DisconnectAsync(DisconnectReason.ByApplication, description);
        }

        /// <summary>
        /// A pooled byte buffer rented from the dedicated SSH packet pool
        /// (<see cref="SshBuffers.Packets"/>) that flows between the async
        /// pumps. Unlike the old ref struct (which could only live on the
        /// stack), this one is stored inside <see cref="_sendChannel"/> and
        /// <see cref="Pipe"/>-backed reads, so it must be a plain struct.
        /// Dispose returns the rental to the pool.
        /// </summary>
        private struct PooledBuffer : IDisposable
        {
            private byte[] _buffer;
            private readonly int _length;

            public PooledBuffer(byte[] buffer, int length)
            {
                _buffer = buffer;
                _length = length;
            }

            public int Length => _length;
            public byte[] Array => _buffer ?? throw new ObjectDisposedException(nameof(PooledBuffer));
            public Span<byte> Span => _buffer.AsSpan(0, _length);
            public ReadOnlySpan<byte> ReadOnlySpan => _buffer.AsSpan(0, _length);
            public Memory<byte> Memory => _buffer.AsMemory(0, _length);
            public ReadOnlyMemory<byte> ReadOnlyMemory => _buffer.AsMemory(0, _length);

            public void Dispose()
            {
                if (_buffer != null)
                {
                    SshBuffers.Packets.Return(_buffer);
                    _buffer = null!;
                }
            }
        }

        /// <summary>
        /// Read exactly <paramref name="length"/> bytes from the receive pipe
        /// into a pooled buffer. Returns an empty buffer when the peer closed
        /// the connection before the requested bytes arrived (EOF). Callers
        /// MUST <c>using</c> the result and consume the bytes before
        /// disposing; the pooled buffer may be larger than the length.
        /// </summary>
        private async ValueTask<PooledBuffer> ReadFromPipeAsync(int length, CancellationToken token)
        {
            // All call sites validate the RFC packet length before reading;
            // this is an internal invariant, not peer input validation.
            Debug.Assert(length >= 0 && length <= MaximumPacketLength + 4 + 64);

            if (length == 0)
                return new PooledBuffer([], 0);

            var result = await _receivePipe.Reader.ReadAtLeastAsync(length, token);
            if (result.IsCanceled || (result.IsCompleted && result.Buffer.Length < length))
                return new PooledBuffer(Array.Empty<byte>(), 0);

            var buffer = SshBuffers.Packets.Rent(length);
            result.Buffer.Slice(0, length).CopyTo(buffer);
            _receivePipe.Reader.AdvanceTo(result.Buffer.GetPosition(length));

            return new PooledBuffer(buffer, length);
        }

        private async Task<string> ReadProtocolVersionAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var result = await _receivePipe.Reader.ReadAsync(token);
                var buffer = result.Buffer;
                var endOfLine = buffer.PositionOf(LineFeed);

                if (endOfLine != null)
                {
                    var lineSequence = buffer.Slice(0, endOfLine.Value);
                    if (lineSequence.Length > 0 && lineSequence.End.GetInteger() > 0)
                    {
                        var lastByte = lineSequence.Slice(lineSequence.Length - 1).First.Span[0];
                        if (lastByte == CarriageReturn)
                            lineSequence = lineSequence.Slice(0, lineSequence.Length - 1);
                    }

                    if (lineSequence.Length > MaximumVersionLineLength)
                    {
                        throw new SshConnectionException(
                            string.Format("Protocol version line exceeds {0} bytes.", MaximumVersionLineLength),
                            DisconnectReason.ProtocolError);
                    }

                    var version = Encoding.ASCII.GetString(lineSequence);
                    _receivePipe.Reader.AdvanceTo(buffer.GetPosition(1, endOfLine.Value));
                    return version;
                }

                if (buffer.Length > MaximumVersionLineLength)
                {
                    // RFC 4253 section 4.2 caps the identification string at
                    // 255 characters; a peer that never sends a newline must
                    // not be able to grow this buffer without bound.
                    throw new SshConnectionException(
                        string.Format("Protocol version line exceeds {0} bytes.", MaximumVersionLineLength),
                        DisconnectReason.ProtocolError);
                }

                if (result.IsCompleted)
                    throw new SshConnectionException("Connection closed before protocol version exchange.", DisconnectReason.ConnectionLost);

                _receivePipe.Reader.AdvanceTo(buffer.Start, buffer.End);
            }
            throw new OperationCanceledException();
        }

        /// <summary>
        /// Validates the client identification string (RFC 4253 section 4.2):
        /// "SSH-2.0-softwareversion [SP comments]". The software version must
        /// be non-empty printable US-ASCII without spaces; the optional
        /// comment may contain spaces but no control characters. Replaces the
        /// former unanchored regex, which accepted an embedded "SSH-2.0-"
        /// anywhere in the line, and the follow-up check that rejected every
        /// space and therefore refused normal Unix banners such as
        /// "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20".
        /// </summary>
        internal static bool IsSupportedClientVersion(string version)
        {
            const string prefix = "SSH-2.0-";
            if (string.IsNullOrEmpty(version)
                || !version.StartsWith(prefix, StringComparison.Ordinal))
                return false;

            var softwareStart = prefix.Length;
            var commentStart = version.IndexOf(' ', softwareStart);
            var softwareEnd = commentStart < 0 ? version.Length : commentStart;

            if (softwareEnd == softwareStart)
                return false;

            for (var i = softwareStart; i < softwareEnd; i++)
            {
                var c = version[i];
                if (c < 0x21 || c > 0x7E)
                    return false;
            }

            // The comment is optional; when present it may contain spaces
            // (0x20) but still no control characters or non-ASCII bytes.
            for (var i = commentStart + 1; commentStart >= 0 && i < version.Length; i++)
            {
                var c = version[i];
                if (c < 0x20 || c > 0x7E)
                    return false;
            }

            return true;
        }
        #endregion

        #region Message operations
        private async Task<Message> ReceiveMessageAsync(CancellationToken token)
        {
            var useAlg = _algorithms != null;
            var isEtm = useAlg && _algorithms.ClientHmacIsEtm;
            var isAead = useAlg && _algorithms.ClientEncryption.IsAead;

            // AEAD (RFC 5647 section 3): layout [packet_length(4, plaintext)][ciphertext][tag(16)].
            // packet_length is plaintext (same as ETM) but covers only the
            // ciphertext portion - NOT the tag. The GCM tag replaces the HMAC
            // and authenticates the ciphertext (the plaintext length field is
            // validated separately as bounded by MaximumPacketLength).
            if (isAead)
            {
                // lenBuf is the 4-byte plaintext packet_length that GCM uses
                // as Additional Authenticated Data. Dispose after DecryptAead
                // consumes it.
                using var lenBuf = await ReadFromPipeAsync(4, token);
                if (lenBuf.Length == 0) return null;
                // chacha20-poly1305@openssh.com encrypts the packet_length field,
                // AES-GCM transmits it plaintext. DecryptPacketLength recovers the
                // plaintext length either way before it can be validated/bounded.
                var packetLength = _algorithms.ClientEncryption.DecryptPacketLength(_inboundPacketSequence, lenBuf.Span);
                if (packetLength < MinimumPacketLength || packetLength > MaximumPacketLength)
                {
                    throw new SshConnectionException(
                        string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                            (uint)packetLength, MinimumPacketLength, MaximumPacketLength),
                        DisconnectReason.ProtocolError);
                }

                // packetLength bytes of ciphertext: padding_length || payload || padding,
                // followed by the 16-byte auth tag. Per RFC 5647 section 7.3 the 4-byte
                // plaintext packet_length (lenBuf) is GCM's Additional Authenticated
                // Data -- authenticated but not encrypted, covered by the tag.
                var tagLength = _algorithms.ClientEncryption.TagBytes;
                using var ciphertextWithTag = await ReadFromPipeAsync(packetLength + tagLength, token);
                if (ciphertextWithTag.Length == 0) return null;

                // Decrypt straight into a pooled buffer (the plaintext is exactly
                // packetLength bytes). The rental is returned in finally after
                // Decompress has copied the payload out, so the receive path
                // allocates no plaintext array per packet.
                var plaintext = SshBuffers.Packets.Rent(packetLength);
                var handedOff = false;
                try
                {
                    // lengthField is the 4 on-wire length bytes: GCM's AAD, and the
                    // chacha20-poly1305 tag input (the encrypted length is passed
                    // verbatim - the transform decrypts/authenticates it itself).
                    _algorithms.ClientEncryption.DecryptAead(
                        _inboundPacketSequence,
                        lenBuf.ReadOnlySpan,
                        ciphertextWithTag.Array.AsSpan(0, packetLength + tagLength),
                        plaintext);

                    var paddingLength = plaintext[0];
                    var dataLength = ValidatePayloadLength(paddingLength, packetLength);
                    var data = plaintext.AsMemory(1, dataLength);
                    // none-compression is the identity: hand the decrypted
                    // slice straight to LoadMessage instead of ToArray()'ing
                    // a copy. Ownership of the rental moves to _dispatchBuffer
                    // and is released only after the message has been
                    // dispatched, so no other thread can recycle it.
                    if (_algorithms.ClientCompression.IsIdentity)
                    {
                        _dispatchBuffer = new PooledBuffer(plaintext, packetLength);
                        handedOff = true;
                        return LoadMessage(data.Span[0], data, packetLength);
                    }

                    var dataArray = _algorithms.ClientCompression.Decompress(data).ToArray();
                    return LoadMessage(dataArray[0], dataArray, packetLength);
                }
                catch (CryptographicException)
                {
                    // GCM tag mismatch is the AEAD equivalent of an HMAC failure --
                    // RFC 4253 section 6.4 mandates connection termination with MAC_ERROR.
                    throw new SshConnectionException("Invalid AEAD tag", DisconnectReason.MacError);
                }
                finally
                {
                    if (!handedOff)
                        SshBuffers.Packets.Return(plaintext);
                }
            }

            // OpenSSH Encrypt-then-MAC (draft-miller-secsh-etm): packet_length is NOT encrypted.
            // Layout: [length(4, plaintext)][encrypt(padding_length||payload||padding)][MAC].
            if (isEtm)
            {
                using var lenBuf = await ReadFromPipeAsync(4, token);
                if (lenBuf.Length == 0) return null;
                var lenSpan = lenBuf.Span;
                var packetLength = lenSpan[0] << 24 | lenSpan[1] << 16 | lenSpan[2] << 8 | lenSpan[3];
                if (packetLength < MinimumPacketLength || packetLength > MaximumPacketLength)
                {
                    throw new SshConnectionException(
                        string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                            (uint)packetLength, MinimumPacketLength, MaximumPacketLength),
                        DisconnectReason.ProtocolError);
                }

                // packetLength bytes of ciphertext: padding_length || payload || padding.
                var cipher = await ReadFromPipeAsync(packetLength, token);
                if (cipher.Length == 0) return null;

                var handedOff = false;
                try
                {
                    // clientMacBuf is disposed right after the SequenceEqual
                    // comparison, before we touch the cipher buffer again.
                    using var clientMacBuf = await ReadFromPipeAsync(_algorithms.ClientHmac.DigestLength, token);
                    if (clientMacBuf.Length == 0) return null;
                    if (!VerifyHmac(_algorithms.ClientHmac, lenBuf.ReadOnlySpan, cipher.ReadOnlySpan, _inboundPacketSequence, clientMacBuf.Span))
                    {
                        throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                    }

                    // Transform exactly packetLength bytes: the buffer is an
                    // ArrayPool rental that may be larger than the packet, and
                    // the CTR keystream counter advances by the transform length -
                    // over-advancing would corrupt every subsequent packet.
                    _algorithms.ClientEncryption.Transform(cipher.Array, packetLength, cipher.Array);
                    var paddingLength = cipher.Span[0];
                    var dataLength = ValidatePayloadLength(paddingLength, packetLength);
                    var data = cipher.Memory.Slice(1, dataLength);
                    // none-compression is the identity: hand the decrypted slice
                    // straight to LoadMessage instead of ToArray()'ing a copy.
                    // Ownership is released after dispatch (see _dispatchBuffer).
                    if (_algorithms.ClientCompression.IsIdentity)
                    {
                        _dispatchBuffer = cipher;
                        handedOff = true;
                        return LoadMessage(data.Span[0], data, packetLength);
                    }

                    var dataArray = _algorithms.ClientCompression.Decompress(data).ToArray();

                    return LoadMessage(dataArray[0], dataArray, packetLength);
                }
                finally
                {
                    if (!handedOff)
                        cipher.Dispose();
                }
            }

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ClientEncryption.BlockBytesSize) : 8);
            using var rawFirst = await ReadFromPipeAsync(blockSize, token);
            if (rawFirst.Length == 0) return null;
            if (useAlg)
                _algorithms.ClientEncryption.Transform(rawFirst.Array, blockSize, rawFirst.Array);

            var rawFirstSpan = rawFirst.Span;
            var packetLengthNonEtm = rawFirstSpan[0] << 24 | rawFirstSpan[1] << 16 | rawFirstSpan[2] << 8 | rawFirstSpan[3];
            if (packetLengthNonEtm < MinimumPacketLength || packetLengthNonEtm > MaximumPacketLength)
            {
                throw new SshConnectionException(
                    string.Format("Invalid packet length {0}. Must be between {1} and {2}.",
                        (uint)packetLengthNonEtm, MinimumPacketLength, MaximumPacketLength),
                    DisconnectReason.ProtocolError);
            }

            var paddingLengthNonEtm = rawFirstSpan[4];
            // RFC 4253 section 6: validate padding before sizing any buffer;
            // a hostile padding_length must not produce a negative length.
            var dataLengthNonEtm = ValidatePayloadLength(paddingLengthNonEtm, packetLengthNonEtm);
            var bytesToRead = packetLengthNonEtm - blockSize + 4;

            using var followingBlocks = await ReadFromPipeAsync(bytesToRead, token);
            if (followingBlocks.Length == 0 && bytesToRead > 0) return null;
            if (useAlg && followingBlocks.Length > 0)
                _algorithms.ClientEncryption.Transform(followingBlocks.Array, bytesToRead, followingBlocks.Array);

            var dataNonEtm = new byte[dataLengthNonEtm];
            var fromFirst = Math.Min(dataLengthNonEtm, blockSize - 5);
            if (fromFirst > 0)
                rawFirst.Span.Slice(5, fromFirst).CopyTo(dataNonEtm);
            if (bytesToRead > 0)
                followingBlocks.Span.Slice(0, dataLengthNonEtm - fromFirst).CopyTo(dataNonEtm.AsSpan(fromFirst));

            if (useAlg)
            {
                // clientMacBuf is disposed after the SequenceEqual comparison,
                // before we re-read the cipher for Decompress.
                using var clientMacBuf = await ReadFromPipeAsync(_algorithms.ClientHmac.DigestLength, token);
                if (clientMacBuf.Length == 0) return null;
                if (!VerifyHmac(_algorithms.ClientHmac, rawFirst.ReadOnlySpan, followingBlocks.ReadOnlySpan, _inboundPacketSequence, clientMacBuf.Span))
                {
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                }

                // none-compression is the identity: dataNonEtm is already the
                // plaintext payload, so skip the ToArray() round-trip copy.
                if (!_algorithms.ClientCompression.IsIdentity)
                    dataNonEtm = _algorithms.ClientCompression.Decompress(dataNonEtm).ToArray();
            }

            var typeNumber = dataNonEtm[0];
            return LoadMessage(typeNumber, dataNonEtm, packetLengthNonEtm);
        }

        /// <summary>
        /// Validates the RFC 4253 section 6 padding and returns the payload
        /// length: <c>packet_length - padding_length - 1</c>. Padding must be
        /// at least 4 bytes and at least one payload byte (the message
        /// number) must remain.
        /// </summary>
        private static int ValidatePayloadLength(byte paddingLength, int packetLength)
        {
            if (paddingLength < 4 || packetLength < paddingLength + 2)
            {
                throw new SshConnectionException(
                    string.Format("Invalid padding length {0} for packet length {1}.", paddingLength, packetLength),
                    DisconnectReason.ProtocolError);
            }
            return packetLength - paddingLength - 1;
        }

        /// <summary>
        /// Convert a decrypted payload into a Message instance, then update
        /// inbound sequencing and the keepalive idle clock. Shared by the ETM
        /// and the regular receive paths. Takes a ReadOnlyMemory so identity
        /// (none) compression can hand the decrypted slice through without a
        /// ToArray() copy.
        /// </summary>
        private Message LoadMessage(byte typeNumber, ReadOnlyMemory<byte> data, int packetLength)
        {
            var implemented = MessageRegistry.TryCreate(typeNumber, out var message);
            if (!implemented)
                message = new UnknownMessage { SequenceNumber = _inboundPacketSequence, UnknownMessageType = typeNumber };

            if (Log.IsEnabled(LogLevel.Trace))
            {
                Log.Trace(implemented
                    ? $"Recv msg={message.GetType().Name} len={packetLength} seq={_inboundPacketSequence}"
                    : $"Recv msg=Unknown({typeNumber}) len={packetLength} seq={_inboundPacketSequence}");
            }

            if (implemented)
                message.Load(data);

            // The receive pump is the only inbound writer, but the flow fields
            // are read by senders during rekey checks; interlocked updates
            // remove the per-packet lock from the receive hot path.
            Interlocked.Increment(ref _inboundPacketSequence);
            Interlocked.Add(ref _inboundFlow, (uint)packetLength);

            ConsiderReExchange();

            // Any inbound frame proves the link is alive; refresh the keepalive
            // idle clock so probing does not fire while the peer is active.
            _lastActivity?.Restart();

            return message;
        }

        internal void SendMessage(Message message)
        {
            ArgumentNullException.ThrowIfNull(message);

            // The whole decision-and-frame sequence runs under _locker: the
            // rekey check, the packet sequence number increment and the
            // enqueue must be atomic with respect to NEWKEYS swapping
            // _algorithms, otherwise a message could be encrypted with the
            // old keys but carry the first post-rekey sequence number (or
            // vice versa), corrupting every following packet.
            lock (_locker)
            {
                if (_exchangeContext != null
                    && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
                {
                    // Rekey window: the message is queued by reference and only
                    // framed later (after NEWKEYS). ChannelDataMessage.Data is a
                    // zero-copy slice over a caller/receive buffer that may be
                    // recycled before the flush, so snapshot the payload now to
                    // keep the queued chunk intact. Other messages carry scalar
                    // fields only and are safe to queue as-is.
                    if (_blockedMessages.Count >= MaximumBlockedMessages)
                        throw new SshConnectionException(
                            "Too many messages queued during key exchange.",
                            DisconnectReason.ByApplication);

                    if (message is ChannelDataMessage cdm)
                    {
                        message = new ChannelDataMessage
                        {
                            RecipientChannel = cdm.RecipientChannel,
                            Data = cdm.Data.ToArray(),
                        };
                    }
                    _blockedMessages.Enqueue(message);
                    return;
                }

                SendMessageInternalLocked(message);
            }
        }

        /// <summary>
        /// Frames and enqueues one message. The caller MUST hold
        /// <see cref="_locker"/> so that the packet sequence number, the
        /// active algorithm set and the send queue stay consistent.
        /// </summary>
        private void SendMessageInternalLocked(Message message)
        {
            var useAlg = _algorithms != null;
            var isAead = useAlg && _algorithms.ServerEncryption.IsAead;
            // The "none" compression hot path (the bulk forwarding case) is an
            // identity transform: writing the message payload straight into a
            // pooled writer skips the intermediate byte[] that
            // message.GetPacket() would allocate. Only a real compressor (which
            // returns its own byte[]) produces a standalone payload array.
            var identityCompression = useAlg && _algorithms.ServerCompression.IsIdentity;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ServerEncryption.BlockBytesSize) : 8);

            SshDataWriter payloadWriter = null;
            byte[] payload = null;
            int payloadLength;
            if (useAlg && !identityCompression)
            {
                // Compressor returns a byte[]; keep that array as the payload.
                payload = _algorithms.ServerCompression.Compress(message.GetPacket());
                payloadLength = payload.Length;
            }
            else
            {
                // Reserve packet_length (4) and padding_length (1) inside the
                // pooled writer, so the payload that follows is already in
                // wire position. The frame can then be completed and encrypted
                // without a second assembly buffer.
                payloadWriter = new SshDataWriter();
                try
                {
                    payloadWriter.Write(0u);
                    payloadWriter.Write((byte)0);
                    message.WritePayload(payloadWriter);
                }
                catch
                {
                    payloadWriter.Dispose();
                    throw;
                }
                payloadLength = payloadWriter.Length - 5;
            }

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            //
            // OpenSSH EtM (draft-miller-secsh-etm) and AEAD (RFC 5647) both transmit
            // packet_length in plaintext and the peer validates it immediately,
            // so the padding must make packet_length itself a multiple of the
            // block size (packet_length = payload.Length + padding + 1).
            byte paddingLength;
            if (useAlg && (_algorithms.ServerHmacIsEtm || isAead))
            {
                paddingLength = (byte)(blockSize - (payloadLength + 1) % blockSize);
                if (paddingLength < 4)
                    paddingLength += blockSize;
            }
            else
            {
                paddingLength = (byte)(blockSize - (payloadLength + 5) % blockSize);
                if (paddingLength < 4)
                    paddingLength += blockSize;
            }

            var packetLength = (uint)payloadLength + paddingLength + 1;
            var framedLength = 4 + (int)packetLength;

            if (payloadWriter != null)
                SendIdentityFramed(payloadWriter, paddingLength, packetLength, framedLength, useAlg, isAead);
            else
                SendCompressedFramed(payload, paddingLength, payloadLength, packetLength, framedLength, useAlg, isAead);

            if (Log.IsEnabled(LogLevel.Trace))
            {
                Log.Trace($"Sent msg={message.GetType().Name} seq={_outboundPacketSequence}");
            }

            // Caller holds _locker: advance the sequence only after the frame
            // was successfully built and queued, so a failed send does not
            // desynchronise the packet stream.
            _outboundPacketSequence++;
            _outboundFlow += packetLength;

            ConsiderReExchange();

            // Outbound traffic also proves the link is alive (and advances the
            // peer's ACK), so it counts toward keepalive idle resetting.
            _lastActivity?.Restart();
        }

        /// <summary>
        /// Complete and enqueue a frame whose payload is already written into
        /// <paramref name="writer"/> behind the reserved packet_length and
        /// padding_length fields. When the negotiated cipher allows it the
        /// writer's pooled buffer becomes the wire buffer, so the frame is not
        /// assembled through an additional scratch array. Caller holds
        /// <see cref="_locker"/>.
        /// </summary>
        private void SendIdentityFramed(
            SshDataWriter writer, byte paddingLength, uint packetLength,
            int framedLength, bool useAlg, bool isAead)
        {
            var detached = false;
            try
            {
                RandomNumberGenerator.Fill(writer.Reserve(paddingLength));

                var header = writer.GetSpan(0, 5);
                header[0] = (byte)(packetLength >> 24);
                header[1] = (byte)(packetLength >> 16);
                header[2] = (byte)(packetLength >> 8);
                header[3] = (byte)packetLength;
                header[4] = paddingLength;

                if (!useAlg)
                {
                    // Pre-KEX: no encryption, the plaintext frame goes out as-is.
                    var plaintext = writer.DetachBuffer();
                    detached = true;
                    var enqueued = false;
                    try
                    {
                        EnqueueWire(plaintext, framedLength);
                        enqueued = true;
                    }
                    finally
                    {
                        if (!enqueued)
                            SshBuffers.Packets.Return(plaintext);
                    }
                    return;
                }

                if (isAead)
                {
                    // RFC 5647 section 3 + 7.3: the AEAD transform owns the
                    // length field and appends the tag, and the native GCM call
                    // needs a destination that does not overlap the frame.
                    var finalLength = framedLength + _algorithms.ServerEncryption.TagBytes;
                    var sendBuf = SshBuffers.Packets.Rent(finalLength);
                    var enqueued = false;
                    try
                    {
                        _algorithms.ServerEncryption.EncryptAead(
                            _outboundPacketSequence,
                            writer.GetSpan(0, framedLength),
                            sendBuf.AsSpan(0, finalLength));
                        EnqueueWire(sendBuf, finalLength);
                        enqueued = true;
                    }
                    finally
                    {
                        if (!enqueued)
                            SshBuffers.Packets.Return(sendBuf);
                    }
                    return;
                }

                var macLength = _algorithms.ServerHmac.DigestLength;

                if (_algorithms.ServerHmacIsEtm)
                {
                    // OpenSSH Encrypt-then-MAC: packet_length stays plaintext;
                    // encrypt the body in place, then MAC seq||length||ciphertext
                    // into the slot reserved after the frame.
                    var mac = writer.Reserve(macLength);
                    var buffer = writer.GetBufferArray();
                    var cipherLength = framedLength - 4;
                    _algorithms.ServerEncryption.Transform(buffer, 4, cipherLength, buffer, 4);

                    var frame = writer.GetSpan(0, framedLength);
                    ComputeHmac(_algorithms.ServerHmac, frame[..4], frame[4..framedLength], _outboundPacketSequence, mac);

                    var wire = writer.DetachBuffer();
                    detached = true;
                    var enqueued = false;
                    try
                    {
                        EnqueueWire(wire, framedLength + macLength);
                        enqueued = true;
                    }
                    finally
                    {
                        if (!enqueued)
                            SshBuffers.Packets.Return(wire);
                    }
                    return;
                }

                // RFC 4253: the whole packet is encrypted and the MAC covers
                // the plaintext. CBC cannot be transformed in place safely, so
                // this path keeps a separate wire buffer.
                var final = framedLength + macLength;
                var encrypted = SshBuffers.Packets.Rent(final);
                var written = false;
                try
                {
                    _algorithms.ServerEncryption.Transform(writer.GetBufferArray(), framedLength, encrypted);
                    Span<byte> mac = stackalloc byte[macLength];
                    ComputeHmac(_algorithms.ServerHmac, writer.GetSpan(0, framedLength), ReadOnlySpan<byte>.Empty, _outboundPacketSequence, mac);
                    mac.CopyTo(encrypted.AsSpan(framedLength));
                    EnqueueWire(encrypted, final);
                    written = true;
                }
                finally
                {
                    if (!written)
                        SshBuffers.Packets.Return(encrypted);
                }
            }
            finally
            {
                if (!detached)
                    writer.Dispose();
            }
        }

        /// <summary>
        /// Frame and enqueue a payload produced by a real compressor. The
        /// compressor returns a standalone array, so this path still assembles
        /// the frame in a pool rental before encryption. Caller holds
        /// <see cref="_locker"/>.
        /// </summary>
        private void SendCompressedFramed(
            byte[] payload, byte paddingLength, int payloadLength,
            uint packetLength, int framedLength, bool useAlg, bool isAead)
        {
            var scratch = SshBuffers.Packets.Rent(framedLength);
            try
            {
                var frame = scratch.AsSpan(0, framedLength);
                frame[0] = (byte)(packetLength >> 24);
                frame[1] = (byte)(packetLength >> 16);
                frame[2] = (byte)(packetLength >> 8);
                frame[3] = (byte)packetLength;
                frame[4] = paddingLength;
                payload.AsSpan().CopyTo(frame.Slice(5));
                RandomNumberGenerator.Fill(frame.Slice(5 + payloadLength, paddingLength));

                var finalLength = framedLength;
                if (useAlg)
                {
                    if (isAead)
                        finalLength += _algorithms.ServerEncryption.TagBytes;
                    else
                        finalLength += _algorithms.ServerHmac.DigestLength;
                }

                var sendBuf = SshBuffers.Packets.Rent(finalLength);
                var enqueued = false;
                try
                {
                    var wire = sendBuf.AsSpan(0, finalLength);

                    if (useAlg)
                    {
                        if (isAead)
                        {
                            _algorithms.ServerEncryption.EncryptAead(_outboundPacketSequence, frame, wire);
                        }
                        else if (_algorithms.ServerHmacIsEtm)
                        {
                            var cipherLen = framedLength - 4;
                            _algorithms.ServerEncryption.Transform(scratch, 4, cipherLen, scratch, 4);

                            Span<byte> mac = stackalloc byte[_algorithms.ServerHmac.DigestLength];
                            ComputeHmac(_algorithms.ServerHmac, frame.Slice(0, 4), frame.Slice(4, cipherLen), _outboundPacketSequence, mac);

                            frame.Slice(0, 4 + cipherLen).CopyTo(wire);
                            mac.CopyTo(wire.Slice(4 + cipherLen));
                        }
                        else
                        {
                            _algorithms.ServerEncryption.Transform(scratch, framedLength, sendBuf);
                            Span<byte> mac = stackalloc byte[_algorithms.ServerHmac.DigestLength];
                            ComputeHmac(_algorithms.ServerHmac, frame, ReadOnlySpan<byte>.Empty, _outboundPacketSequence, mac);
                            mac.CopyTo(wire.Slice(framedLength));
                        }
                    }
                    else
                    {
                        // Pre-KEX: no encryption; the plaintext frame goes out as-is.
                        frame.CopyTo(wire);
                    }

                    EnqueueWire(sendBuf, finalLength);
                    enqueued = true;
                }
                finally
                {
                    // Ownership of sendBuf transfers to the enqueued
                    // PooledBuffer only on success; a crypto/enqueue failure
                    // must not leak the array-pool rental.
                    if (!enqueued)
                        SshBuffers.Packets.Return(sendBuf);
                }
            }
            finally
            {
                SshBuffers.Packets.Return(scratch);
            }
        }

        /// <summary>
        /// Hand one completed wire buffer to the send pump under the outbound
        /// byte budget. Does not take ownership: on failure the caller still
        /// owns <paramref name="buffer"/> and must return it.
        /// </summary>
        private void EnqueueWire(byte[] buffer, int length)
        {
            if (!TryReserveOutboundBuffer(length))
            {
                OnOutboundQueueOverflow("Outbound queue exceeded its memory budget.");
                throw new SshConnectionException(
                    "Outbound queue exceeded its memory budget.",
                    DisconnectReason.ByApplication);
            }

            if (!_sendChannel.Writer.TryWrite(new PooledBuffer(buffer, length)))
            {
                ReleaseOutboundBuffer(length);
                OnOutboundQueueOverflow("Outbound packet queue is full.");
                throw new SshConnectionException(
                    "Could not enqueue message for sending.",
                    DisconnectReason.ByApplication);
            }
        }

        /// <summary>
        /// Reserve part of the session-wide outbound byte budget. Channels use
        /// the same budget for data waiting on peer window credit, so the two
        /// queues cannot independently grow to their own limits.
        /// </summary>
        internal bool TryReserveOutboundBuffer(int length)
        {
            var total = Interlocked.Add(ref _bufferedOutboundBytes, length);
            if (total <= Limits.MaximumOutboundBytes)
                return true;

            Interlocked.Add(ref _bufferedOutboundBytes, -length);
            return false;
        }

        internal void ReleaseOutboundBuffer(int length)
            => Interlocked.Add(ref _bufferedOutboundBytes, -length);

        /// <summary>
        /// Gets the bytes currently held by the shared outbound budget
        /// (framed packets plus channel backlogs).
        /// </summary>
        public long BufferedOutboundBytes => Interlocked.Read(ref _bufferedOutboundBytes);

        private void ConsiderReExchange(bool force = false)
        {
            lock (_locker)
            {
                if (_exchangeContext != null)
                    return;
                if (!force && Volatile.Read(ref _inboundFlow) + _outboundFlow <= 1024 * 1024 * 512) // 0.5 GiB
                    return;

                Log.Debug(force ? "Key exchange triggered (forced)."
                    : "Key exchange triggered (traffic threshold reached).");

                // Publish the context and its KEXINIT payload before sending:
                // once _exchangeContext is non-null, SendMessage from other
                // threads parks application traffic instead of racing the
                // rekey.
                _exchangeContext = new ExchangeContext();
                var kexInitMessage = LoadKexInitMessage();
                _exchangeContext.ServerKexInitPayload = kexInitMessage.GetPacket();
                SendMessageInternalLocked(kexInitMessage);
            }
        }

        internal bool TrySendMessage(Message message)
        {
            ArgumentNullException.ThrowIfNull(message);

            try
            {
                SendMessage(message);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private Message LoadKexInitMessage()
        {
            // RFC 8308: advertise "ext-info-s" inside the kex_algorithms
            // name-list so the client knows we accept SSH_MSG_EXT_INFO.
            var kexAlgs = new List<string>(_keyExchangeAlgorithms.Keys) { "ext-info-s" };

            // OpenSSH strict KEX (Terrapin mitigation). The pseudo-algorithm
            // is only valid in the initial KEXINIT; later rekeys must omit it.
            if (!_initialKexInitReceived)
                kexAlgs.Add(StrictKexServerMarker);

            var message = new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = kexAlgs.ToArray(),
                ServerHostKeyAlgorithms = _hostKeyAlgorithmNames,
                EncryptionAlgorithmsClientToServer = [.. _encryptionAlgorithms.Keys],
                EncryptionAlgorithmsServerToClient = [.. _encryptionAlgorithms.Keys],
                MacAlgorithmsClientToServer = [.. _hmacAlgorithms.Keys],
                MacAlgorithmsServerToClient = [.. _hmacAlgorithms.Keys],
                CompressionAlgorithmsClientToServer = [.. _compressionAlgorithms.Keys],
                CompressionAlgorithmsServerToClient = [.. _compressionAlgorithms.Keys],
                LanguagesClientToServer = [""],
                LanguagesServerToClient = [""],
                FirstKexPacketFollows = false,
                Reserved = 0,
            };

            return message;
        }
        #endregion

        #region Handle messages
        // Compile-time dispatch replacing the former (dynamic) binder. Order
        // matters: concrete KEX subclasses must be matched before their
        // KeyExchangeXInitMessage base, mirroring the old most-specific
        // overload binding. Every message number MessageRegistry creates has
        // a case here; UnknownMessage is answered by the receive loop before
        // dispatch ever sees it.
        private void HandleMessageCore(Message message)
        {
            switch (message)
            {
                case DisconnectMessage m: HandleMessage(m); break;
                case KeyExchangeInitMessage m: HandleMessage(m); break;
                case KeyExchangeDhInitMessage m: HandleMessage(m); break;
                case KeyExchangeECDhInitMessage m: HandleMessage(m); break;
                case KeyExchangeXInitMessage m: HandleMessage(m); break;
                case NewKeysMessage m: HandleMessage(m); break;
                case ExtInfoMessage m: HandleMessage(m); break;
                case UnimplementedMessage m: HandleMessage(m); break;
                case GlobalRequestMessage m: HandleMessage(m); break;
                case RequestSuccessMessage m: HandleMessage(m); break;
                case RequestFailureMessage m: HandleMessage(m); break;
                case ServiceRequestMessage m: HandleMessage(m); break;
                case UserAuthServiceMessage m: HandleMessage(m); break;
                case ConnectionServiceMessage m: HandleMessage(m); break;
            }
        }

        private void HandleMessage(DisconnectMessage message)
        {
            Disconnect(message.ReasonCode, message.Description);
        }

        private void HandleMessage(KeyExchangeInitMessage message)
        {
            ConsiderReExchange(true);

            // OpenSSH strict KEX: the marker is only valid in the initial
            // KEXINIT, and the initial KEXINIT must be the first packet the
            // client sends.
            if (!_initialKexInitReceived)
            {
                _initialKexInitReceived = true;
                if (message.KeyExchangeAlgorithms.Contains(StrictKexClientMarker))
                {
                    if (_preKexPacketSeen)
                        throw new SshConnectionException(
                            "strict KEX violation: non-KEX packet received before the initial KEXINIT.",
                            DisconnectReason.ProtocolError);

                    _strictKex = true;
                    Log.Debug("strict KEX negotiated.");
                }
            }

            if (Log.IsEnabled(LogLevel.Info))
                Log.Info("Client cipher suites: " +
                    $"hostkey=[{string.Join(",", message.ServerHostKeyAlgorithms)}], kex=[{string.Join(",", message.KeyExchangeAlgorithms)}], " +
                    $"cipher ctos=[{string.Join(",", message.EncryptionAlgorithmsClientToServer)}], stoc=[{string.Join(",", message.EncryptionAlgorithmsServerToClient)}], " +
                    $"hmac ctos=[{string.Join(",", message.MacAlgorithmsClientToServer)}], stoc=[{string.Join(",", message.MacAlgorithmsServerToClient)}], " +
                    $"compression ctos=[{string.Join(",", message.CompressionAlgorithmsClientToServer)}], stoc=[{string.Join(",", message.CompressionAlgorithmsServerToClient)}].");

            KeysExchanged?.Invoke(this, new KeyExchangeArgs(this)
            {
                CompressionAlgorithmsClientToServer = message.CompressionAlgorithmsClientToServer,
                CompressionAlgorithmsServerToClient = message.CompressionAlgorithmsServerToClient,
                EncryptionAlgorithmsClientToServer = message.EncryptionAlgorithmsClientToServer,
                EncryptionAlgorithmsServerToClient = message.EncryptionAlgorithmsServerToClient,
                KeyExchangeAlgorithms = message.KeyExchangeAlgorithms,
                LanguagesClientToServer = message.LanguagesClientToServer,
                LanguagesServerToClient = message.LanguagesServerToClient,
                MacAlgorithmsClientToServer = message.MacAlgorithmsClientToServer,
                MacAlgorithmsServerToClient = message.MacAlgorithmsServerToClient,
                ServerHostKeyAlgorithms = message.ServerHostKeyAlgorithms
            });

            // RFC 4253 7.1 defines the first_kex_packet_follows guess as the
            // KEY EXCHANGE METHOD plus the SERVER HOST KEY algorithm only.
            // Cipher/MAC/compression choices are negotiated independently and
            // must not invalidate the client's guessed packet, otherwise a
            // client whose first cipher preference is unsupported has its
            // legitimate KEXDH_INIT discarded and the handshake stalls.
            var kexGuess = ChooseAlgorithm([.. _keyExchangeAlgorithms.Keys], message.KeyExchangeAlgorithms, out _exchangeContext.KeyExchange);
            var hostKeyGuess = ChooseAlgorithm(_hostKeyAlgorithmNames, message.ServerHostKeyAlgorithms, out _exchangeContext.PublicKey);
            ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsClientToServer, out _exchangeContext.ClientEncryption);
            ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsServerToClient, out _exchangeContext.ServerEncryption);
            ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsClientToServer, out _exchangeContext.ClientHmac);
            ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsServerToClient, out _exchangeContext.ServerHmac);
            ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsClientToServer, out _exchangeContext.ClientCompression);
            ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsServerToClient, out _exchangeContext.ServerCompression);
            var isGuessed = kexGuess & hostKeyGuess;

            // RFC 4253 7.1: if the client optimistically sent a first KEX
            // packet and its algorithm guess was wrong, discard that packet.
            if (message.FirstKexPacketFollows && !isGuessed)
                _discardNextKexPacket = true;

            // RFC 4253 section 8: the exchange hash covers the KEXINIT packet
            // exactly as transmitted. Re-serialising the parsed fields would
            // drop trailing bytes and normalise non-ASCII name bytes, so keep
            // the raw payload instead.
            _exchangeContext.ClientKexInitPayload = message.RawPayload.ToArray();

            Log.Info($"hostkey={_exchangeContext.PublicKey}, Negotiated: kex={_exchangeContext.KeyExchange}, " +
                $"ctos={_exchangeContext.ClientEncryption}:{_exchangeContext.ClientHmac}:{_exchangeContext.ClientCompression}, " +
                $"stoc={_exchangeContext.ServerEncryption}:{_exchangeContext.ServerHmac}:{_exchangeContext.ServerCompression}.");

            // RFC 8308: remember whether the client supports EXT_INFO.
            _clientAdvertisedExtInfo = message.PeerExtensions.Contains("ext-info-c");
        }

        private void HandleMessage(KeyExchangeXInitMessage message)
        {
            // RFC 8731 / RFC 5656: the message format (mpint e for DH, string Q
            // for ECDH) is determined by the negotiated KEX algorithm, NOT the
            // host key algorithm. curve25519-sha256 uses the ECDH message path
            // regardless of the host key type (e.g. RSA), which the old
            // host-key-based dispatch would have misrouted to the DH parser.
            var kex = _exchangeContext.KeyExchange;
            if (kex.StartsWith("curve25519-", StringComparison.Ordinal) || kex.StartsWith("ecdh-", StringComparison.Ordinal)
                || kex.StartsWith("mlkem", StringComparison.Ordinal) || kex.StartsWith("sntrup", StringComparison.Ordinal))
                message = Message.LoadFrom<KeyExchangeECDhInitMessage>(message);
            else if (kex.StartsWith("diffie-hellman-", StringComparison.Ordinal))
                message = Message.LoadFrom<KeyExchangeDhInitMessage>(message);
            else
                throw new InvalidOperationException($"Unknown key exchange algorithm: {kex}.");
            HandleMessageCore(message);
        }

        private PublicKeyAlgorithm GetHostKey(string algorithmName)
        {
            lock (_locker)
            {
                if (!_hostKeyInstances.TryGetValue(algorithmName, out var hostKey))
                {
                    hostKey = _publicKeyAlgorithms[algorithmName](_hostKey[algorithmName]);
                    _hostKeyInstances.Add(algorithmName, hostKey);
                }
                return hostKey;
            }
        }

        private void HandleMessage(KeyExchangeDhInitMessage message)
        {
            KexAlgorithm kexAlg = null;
            CipherInfo clientCipher = null;
            CipherInfo serverCipher = null;
            HmacInfo clientHmac = null;
            HmacInfo serverHmac = null;
            try
            {
                var hostKeyAlg = GetHostKey(_exchangeContext.PublicKey);
                kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange](null);

                clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption](null);
                serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption](null);
                // RFC 5647 section 6: an AEAD direction never uses the
                // negotiated MAC, so do not build a MAC descriptor for it.
                if (!clientCipher.IsAead)
                    clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac](null);
                if (!serverCipher.IsAead)
                    serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac](null);

                var clientExchangeValue = message.E;
                var serverExchangeValue = kexAlg.CreateKeyExchange();
                var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
                var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
                var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, false);

                if (SessionId == null)
                {
                    SessionId = exchangeHash;
                    if (Log.IsEnabled(LogLevel.Info))
                        Log.Info($"Key exchange complete, session id {Convert.ToHexString(exchangeHash, 0, 8)}...");
                }

                _exchangeContext.NewAlgorithms?.Dispose();
                _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

                var reply = new KeyExchangeDhReplyMessage
                {
                    HostKey = hostKeyAndCerts,
                    F = serverExchangeValue,
                    Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
                };

                SendMessage(reply);
            }
            finally
            {
                // A failed exchange must not leave the wrapped native
                // cipher/MAC handles to the finalizer. Each info is a no-op
                // once ComputeEncryption's transform took ownership.
                clientHmac?.Dispose();
                serverHmac?.Dispose();
                clientCipher?.Dispose();
                serverCipher?.Dispose();
                kexAlg?.Dispose();
            }
        }

        private void HandleMessage(KeyExchangeECDhInitMessage message)
        {
            KexAlgorithm kexAlg = null;
            CipherInfo clientCipher = null;
            CipherInfo serverCipher = null;
            HmacInfo clientHmac = null;
            HmacInfo serverHmac = null;
            try
            {
                var hostKeyAlg = GetHostKey(_exchangeContext.PublicKey);
                kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange](null);

                clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption](null);
                serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption](null);
                // RFC 5647 section 6: an AEAD direction never uses the
                // negotiated MAC, so do not build a MAC descriptor for it.
                if (!clientCipher.IsAead)
                    clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac](null);
                if (!serverCipher.IsAead)
                    serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac](null);

                var clientExchangeValue = message.Q;
                // Hybrid PQ/T KEX (e.g. mlkem768x25519-sha256) must parse the
                // client's C_INIT first: the server's S_REPLY embeds the ML-KEM
                // ciphertext, which can only be produced after the client's
                // encapsulation key is known. Classical algorithms (X25519, ECDH,
                // DH) generate their key pair in the ctor, so this order is safe
                // for them too.
                var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
                var serverExchangeValue = kexAlg.CreateKeyExchange();
                var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
                var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, true);

                if (SessionId == null)
                {
                    SessionId = exchangeHash;
                    if (Log.IsEnabled(LogLevel.Info))
                        Log.Info($"Key exchange complete, session id {Convert.ToHexString(exchangeHash, 0, 8)}...");
                }

                _exchangeContext.NewAlgorithms?.Dispose();
                _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

                var reply = new KeyExchangeECDhReplyMessage
                {
                    HostKey = hostKeyAndCerts,
                    Q = serverExchangeValue,
                    Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
                };

                SendMessage(reply);
            }
            finally
            {
                // A failed exchange must not leave the wrapped native
                // cipher/MAC handles to the finalizer. Each info is a no-op
                // once ComputeEncryption's transform took ownership.
                clientHmac?.Dispose();
                serverHmac?.Dispose();
                clientCipher?.Dispose();
                serverCipher?.Dispose();
                kexAlg?.Dispose();
            }
        }

        private void HandleMessage(NewKeysMessage message)
        {
            // RFC 4253 7.3: send SSH_MSG_NEWKEYS before applying the new keys.
            // We deliberately send the server's NEWKEYS here (after receiving the
            // client's NEWKEYS) so that our server's NEWKEYS data segment piggybacks
            // the ACK for the client's NEWKEYS. Otherwise the client's NEWKEYS stays
            // un-ACKed and Nagle blocks the subsequent SERVICE_REQUEST until the
            // delayed-ACK timer fires (~40ms on Linux).
            //
            // The whole switch happens under _locker: NEWKEYS goes out under the
            // old keys, then the algorithm set is swapped, EXT_INFO and every
            // blocked application message are framed under the new keys. A
            // concurrent sender either completes before the swap or gets parked
            // by the still-active _exchangeContext and flushed here.
            // RFC 4253 section 7.3: NEWKEYS is only valid once the key
            // exchange has produced a key set. A peer could otherwise send
            // NEWKEYS immediately after KEXINIT (or as the first packet) and
            // silently downgrade the rest of the session to plaintext.
            if (_exchangeContext?.NewAlgorithms == null)
                throw new SshConnectionException(
                    "SSH_MSG_NEWKEYS received before the key exchange completed.",
                    DisconnectReason.ProtocolError);

            lock (_locker)
            {
                Log.Debug("New keys applied.");
                SendMessageInternalLocked(new NewKeysMessage());

                Interlocked.Exchange(ref _inboundFlow, 0);
                _outboundFlow = 0;
                var previousAlgorithms = _algorithms;
                _algorithms = _exchangeContext.NewAlgorithms;
                _exchangeContext.NewAlgorithms = null;
                _exchangeContext = null;
                _firstKeyExchangeComplete = true;

                // The old cipher/MAC instances cannot be used after the swap;
                // release their native handles deterministically instead of
                // waiting for finalizers. No send can be in flight: the whole
                // swap runs under _locker.
                previousAlgorithms?.Dispose();

                // OpenSSH strict KEX resets the packet sequence numbers to
                // zero after NEWKEYS in both directions. The inbound counter
                // was advanced for the client's NEWKEYS above; the outbound
                // one for ours. The next packet in each direction must use 0.
                if (_strictKex)
                {
                    Interlocked.Exchange(ref _inboundPacketSequence, 0);
                    _outboundPacketSequence = 0;
                }

                // RFC 8308 section 2.2: send SSH_MSG_EXT_INFO as the first
                // message under the new keys, before any blocked messages.
                // Only send when the client advertised "ext-info-c".
                if (_clientAdvertisedExtInfo && _extensionsToSend.Count > 0)
                {
                    SendMessageInternalLocked(new ExtInfoMessage
                    {
                        Extensions = new Dictionary<string, string>(_extensionsToSend)
                    });
                }

                while (_blockedMessages.Count > 0)
                    SendMessageInternalLocked(_blockedMessages.Dequeue());
            }
        }

        /// <summary>
        /// Register a protocol extension to advertise via SSH_MSG_EXT_INFO
        /// (RFC 8308). Call before the first connection is accepted, or at
        /// session setup. Extensions are sent immediately after NEWKEYS
        /// during each key exchange when the peer supports ext-info-c.
        /// </summary>
        /// <param name="name">Extension name (e.g. "server-sig-algs").</param>
        /// <param name="value">Extension value (e.g. "ssh-ed25519,rsa-sha2-512").</param>
        public void RegisterExtension(string name, string value)
        {
            _extensionsToSend[name] = value;
        }

        private void HandleMessage(ExtInfoMessage message)
        {
            // RFC 8308 section 2.2: the client sends SSH_MSG_EXT_INFO
            // right after its NEWKEYS. We do not currently define any
            // client-to-server extensions to act on; acknowledging receipt
            // is sufficient for protocol correctness and future compatibility.
        }

        private void HandleMessage(UnimplementedMessage message)
        {
            // Nothing to do here
        }

        private void HandleMessage(GlobalRequestMessage message)
        {
            // SSH_MSG_GLOBAL_REQUEST (RFC 4254 section 4) can arrive at any
            // time, even before ssh-connection is registered, so we handle it
            // here at the session level rather than forwarding to ConnectionService.
            switch (message.RequestName)
            {
                case "keepalive@openssh.com":
                    // OpenSSH keepalive: no payload, just probe liveness.
                    // Reply SUCCESS when the peer asks for a reply; keep silent
                    // otherwise (want-reply=false is a one-way probe).
                    if (message.WantReply)
                        SendMessage(new RequestSuccessMessage());
                    break;
                default:
                    // Business-related global requests (tcpip-forward, etc.)
                    // belong to the connection service. Forward when registered.
                    // If not registered yet, reply FAILURE per RFC 4254.
                    var conn = GetService<ConnectionService>();
                    if (conn != null)
                    {
                        conn.HandleMessage(message);
                    }
                    else if (message.WantReply)
                    {
                        SendMessage(new RequestFailureMessage());
                    }
                    break;
            }
        }

        private void HandleMessage(RequestSuccessMessage message)
        {
            // SSH_MSG_REQUEST_SUCCESS (RFC 4254 section 4): a peer honoured our
            // keepalive probe. Both SUCCESS and FAILURE prove liveness, so clear
            // the missed-probe counter. The activity clock itself is already
            // refreshed in ReceiveMessage, the single inbound entry point.
            Interlocked.Exchange(ref _missedProbes, 0);
        }

        private void HandleMessage(RequestFailureMessage message)
        {
            // SSH_MSG_REQUEST_FAILURE (RFC 4254 section 4): a peer rejected our
            // global request. For keepalive this still proves liveness, so we
            // do not treat it as an error; same counter reset as for SUCCESS.
            Interlocked.Exchange(ref _missedProbes, 0);
        }

        /// <summary>
        /// Send a keepalive@openssh.com global request to the peer and ask for
        /// a reply. Use this from a server-side idle timer to detect dead
        /// connections before the TCP keepalive timeout fires. The peer's
        /// REQUEST_SUCCESS / REQUEST_FAILURE is handled by the corresponding
        /// HandleMessage overloads; both are treated as proof of liveness.
        /// </summary>
        public void SendGlobalKeepalive()
        {
            SendMessage(new GlobalRequestMessage
            {
                RequestName = "keepalive@openssh.com",
                WantReply = true,
            });
        }

        /// <summary>
        /// Enable or update server-side keepalive probing. After the session
        /// has been idle (no inbound or outbound traffic) for <paramref name="idle"/>,
        /// the server sends a keepalive@openssh.com global request every
        /// <paramref name="idle"/> interval. Once three consecutive probes
        /// have gone unanswered the session is torn down. Pass a non-positive
        /// value to disable probing. Calling this before the session is
        /// established is allowed; the idle clock starts immediately.
        /// </summary>
        public void ConfigureKeepalive(TimeSpan idle)
        {
            lock (_locker)
            {
                _keepaliveIdle = idle;

                if (idle <= TimeSpan.Zero)
                {
                    _missedProbes = 0;
                    _lastProbeTimestamp = 0;
                    Log.Debug("Keepalive probing disabled.");
                    RescheduleLifecycleTimerLocked();
                    return;
                }

                Log.Debug($"Keepalive probing enabled, idle threshold {idle}.");

                _lastActivity ??= Stopwatch.StartNew();
                _lastProbeTimestamp = 0;
                RescheduleLifecycleTimerLocked();
            }
        }

        /// <summary>
        /// Schedules the single per-session lifecycle timer at the shortest
        /// configured period; each tick evaluates both the keepalive and the
        /// inactivity rule against their own thresholds. One timer per session
        /// instead of one per feature. Caller holds <see cref="_locker"/>.
        /// </summary>
        private void RescheduleLifecycleTimerLocked()
        {
            var period = TimeSpan.Zero;
            if (_keepaliveIdle > TimeSpan.Zero)
                period = _keepaliveIdle;
            if (_inactivityTimeout > TimeSpan.Zero
                && (period <= TimeSpan.Zero || _inactivityTimeout < period))
                period = _inactivityTimeout;

            if (period <= TimeSpan.Zero)
            {
                _lifecycleTimer?.Dispose();
                _lifecycleTimer = null;
                return;
            }

            _lastActivity ??= Stopwatch.StartNew();
            var due = (int)Math.Min(period.TotalMilliseconds, int.MaxValue);
            if (_lifecycleTimer == null)
                _lifecycleTimer = new Timer(LifecycleTick, null, due, due);
            else
                _lifecycleTimer.Change(due, due);
        }

        private void LifecycleTick(object state)
        {
            if (_disconnected || _socket == null)
                return;

            var idle = _lastActivity?.Elapsed ?? TimeSpan.Zero;

            // The inactivity cap is a hard limit that needs no cooperation
            // from the peer, so it is evaluated before any probing.
            if (_inactivityTimeout > TimeSpan.Zero && idle >= _inactivityTimeout)
            {
                Log.Warn($"No traffic for {_inactivityTimeout}; disconnecting.");
                Disconnect(DisconnectReason.ByApplication, "Connection inactive for too long.");
                return;
            }

            if (_keepaliveIdle <= TimeSpan.Zero || idle < _keepaliveIdle)
                return;

            // The timer may run at the inactivity period, which can be shorter
            // than the keepalive interval; keep probes on their own cadence.
            if (_lastProbeTimestamp != 0
                && Stopwatch.GetElapsedTime(_lastProbeTimestamp) < _keepaliveIdle)
                return;
            _lastProbeTimestamp = Stopwatch.GetTimestamp();

            // Idle window elapsed: probe and count. If the peer answers, the
            // RequestSuccess/Failure handler clears the counter; otherwise we
            // keep accumulating until MaxMissedProbes, then tear down.
            //
            // SendGlobalKeepalive() is a non-blocking enqueue; it can still
            // fail (channel completed / socket disposed) if a concurrent
            // disconnect raced the probe. Guard the send and re-check
            // _disconnected afterwards so a stale probe is never counted.
            try
            {
                SendGlobalKeepalive();
            }
            catch (Exception ex) when (ex is ObjectDisposedException or SshConnectionException)
            {
                // The session was torn down by a concurrent disconnect - the
                // probe went nowhere, nothing more to do.
                return;
            }

            // Re-check: a concurrent disconnect may have raced the probe.
            if (_disconnected)
                return;

            var missed = Interlocked.Increment(ref _missedProbes);
            if (missed >= MaxMissedProbes)
            {
                Log.Warn($"Keepalive probe unanswered {missed} times; disconnecting.");
                Disconnect(DisconnectReason.ByApplication, "Keepalive timeout.");
            }
            else
            {
                Log.Debug($"Keepalive probe {missed}/{MaxMissedProbes} unanswered.");
            }
        }

        /// <summary>
        /// Enable or update the server-side inactivity timeout: when no
        /// traffic has flowed in either direction for <paramref name="timeout"/>,
        /// the session is disconnected. The shared idle clock refreshes on
        /// every inbound byte (raw, including the pre-handshake version
        /// exchange) and every outbound frame, so a session the server is
        /// actively streaming to is never killed - a wedged slow consumer is
        /// still reaped once TCP backpressure stalls the send pump. Unlike
        /// <see cref="ConfigureKeepalive"/> this is a hard cap that needs no
        /// cooperation from the client. Pass a non-positive value to disable
        /// the timeout. Calling this before the session is established is
        /// allowed; the idle clock starts immediately. A server-wide default
        /// can be set through <see cref="SshServer.InactivityTimeout"/>.
        /// </summary>
        public void ConfigureInactivityTimeout(TimeSpan timeout)
        {
            lock (_locker)
            {
                _inactivityTimeout = timeout;

                if (timeout <= TimeSpan.Zero)
                {
                    Log.Debug("Inactivity timeout disabled.");
                    RescheduleLifecycleTimerLocked();
                    return;
                }

                Log.Debug($"Inactivity timeout enabled, threshold {timeout}.");

                _lastActivity ??= Stopwatch.StartNew();
                RescheduleLifecycleTimerLocked();
            }
        }

        private void HandleMessage(ServiceRequestMessage message)
        {
            SshService service = RegisterService(message.ServiceName);
            if (service != null)
            {
                SendMessage(new ServiceAcceptMessage(message.ServiceName));
                return;
            }
            throw new SshConnectionException(string.Format("Service \"{0}\" not available.", message.ServiceName),
                DisconnectReason.ServiceNotAvailable);
        }

        private void HandleMessage(UserAuthServiceMessage message)
        {
            var service = GetService<UserAuthService>();
            // RFC 4252 section 5.1: the client MUST NOT send further
            // USERAUTH_REQUESTs after a success; ignore them instead of
            // re-running authentication against a privileged session.
            if (service != null && !service.IsAuthenticated)
                service.HandleMessageCore(message);
        }

        private void HandleMessage(ConnectionServiceMessage message)
        {
            var service = GetService<ConnectionService>();
            if (service != null)
                service.HandleMessageCore(message);
        }
        #endregion

        private static bool ChooseAlgorithm(string[] serverAlgorithms, string[] clientAlgorithms, out string chosenAlgorithm)
        {
            foreach (var clientAlgorithm in clientAlgorithms)
                if (serverAlgorithms.Contains(clientAlgorithm))
                {
                    chosenAlgorithm = clientAlgorithm;
                    return clientAlgorithm == clientAlgorithms[0];
                }

            throw new SshConnectionException("Failed to negotiate algorithm.", DisconnectReason.KeyExchangeFailed);
        }

        private byte[] ComputeExchangeHash(KexAlgorithm kexAlg, byte[] hostKeyAndCerts, byte[] clientExchangeValue, byte[] serverExchangeValue, byte[] sharedSecret, bool isEcdh)
        {
            var writer = new SshDataWriter(32 + ClientVersion.Length + ServerVersion.Length + _exchangeContext.ClientKexInitPayload.Length + _exchangeContext.ServerKexInitPayload.Length + hostKeyAndCerts.Length + clientExchangeValue.Length + serverExchangeValue.Length + sharedSecret.Length)
                .Write(ClientVersion, Encoding.ASCII)
                .Write(ServerVersion, Encoding.ASCII)
                .WriteBinary(_exchangeContext.ClientKexInitPayload)
                .WriteBinary(_exchangeContext.ServerKexInitPayload)
                .WriteBinary(hostKeyAndCerts);
            if (isEcdh)
            {
                writer.WriteBinary(clientExchangeValue);
                writer.WriteBinary(serverExchangeValue);
            }
            else
            {
                writer.WriteMpint(clientExchangeValue);
                writer.WriteMpint(serverExchangeValue);
            }
            // Hybrid PQ/T methods carry K as an SSH string (the hash output);
            // classical methods use the RFC 4253 mpint encoding.
            if (kexAlg.SharedSecretIsString)
                writer.WriteBinary(sharedSecret);
            else
                writer.WriteMpint(sharedSecret);
            return kexAlg.ComputeHash(writer.ToByteArray());
        }

        private Algorithms ComputeEncryption(KexAlgorithm kexAlg, PublicKeyAlgorithm hostKeyAlg, byte[] exchangeHash, CipherInfo clientCipher, CipherInfo serverCipher, HmacInfo clientHmac, HmacInfo serverHmac, byte[] sharedSecret)
        {
            // IV length is algorithm-specific: AES-CBC/CTR use a full block (16
            // bytes), AES-GCM the full 12-byte nonce (4-byte fixed field plus
            // the 8-byte invocation-counter seed, RFC 5647 section 7.1), whose
            // counter half is advanced per packet by GcmModeCryptoTransform.
            var clientCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.IVSize, sharedSecret, 'A');
            var serverCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.IVSize, sharedSecret, 'B');
            var clientCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.KeySize >> 3, sharedSecret, 'C');
            var serverCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.KeySize >> 3, sharedSecret, 'D');

            EncryptionAlgorithm clientEncryption = null;
            EncryptionAlgorithm serverEncryption = null;
            HmacAlgorithm clientHmacAlg = null;
            HmacAlgorithm serverHmacAlg = null;
            CompressionAlgorithm clientCompression = null;
            CompressionAlgorithm serverCompression = null;
            try
            {
                clientEncryption = clientCipher.Cipher(clientCipherKey, clientCipherIV, false);
                serverEncryption = serverCipher.Cipher(serverCipherKey, serverCipherIV, true);

                // AEAD (GCM) replaces the separate HMAC with an inline auth tag.
                // RFC 5647 section 6: the negotiated MAC name is still carried in KEX_INIT
                // and the MAC key is still derived for compatibility, but it MUST NOT
                // be used to authenticate packets - the GCM tag does that. We skip
                // deriving the MAC key for the AEAD direction entirely (nothing reads
                // ClientHmac/ServerHmac when the corresponding cipher IsAead), and
                // leave the HmacAlgorithm slots null so any accidental use fails loud.
                if (!clientEncryption.IsAead)
                {
                    var clientHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientHmac.KeySize >> 3, sharedSecret, 'E');
                    clientHmacAlg = clientHmac.Hmac(clientHmacKey);
                }
                if (!serverEncryption.IsAead)
                {
                    var serverHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverHmac.KeySize >> 3, sharedSecret, 'F');
                    serverHmacAlg = serverHmac.Hmac(serverHmacKey);
                }

                // Both compressions must be created inside the try: when the
                // server direction's factory fails, the client-side instance
                // created just before it is already live and must be released.
                clientCompression = _compressionAlgorithms[_exchangeContext.ClientCompression](null);
                serverCompression = _compressionAlgorithms[_exchangeContext.ServerCompression](null);

                return new Algorithms
                {
                    KeyExchange = kexAlg,
                    PublicKey = hostKeyAlg,
                    ClientEncryption = clientEncryption,
                    ServerEncryption = serverEncryption,
                    ClientHmac = clientHmacAlg,
                    ServerHmac = serverHmacAlg,
                    ClientCompression = clientCompression,
                    ServerCompression = serverCompression,
                    // An AEAD direction has no HMAC, so its EtM flag is
                    // meaningless; neither HmacInfo exists in that case.
                    ClientHmacIsEtm = clientHmacAlg != null && clientHmac.IsEtm,
                    ServerHmacIsEtm = serverHmacAlg != null && serverHmac.IsEtm,
                };
            }
            catch
            {
                // Do not leave half-built cipher/MAC/compression handles to
                // the finalizer when key derivation or a factory fails
                // mid-construction.
                (serverCompression as IDisposable)?.Dispose();
                (clientCompression as IDisposable)?.Dispose();
                serverHmacAlg?.Dispose();
                clientHmacAlg?.Dispose();
                serverEncryption?.Dispose();
                clientEncryption?.Dispose();
                throw;
            }
        }

        private byte[] ComputeEncryptionKey(KexAlgorithm kexAlg, byte[] exchangeHash, int blockSize, byte[] sharedSecret, char letter)
            => DeriveKey(kexAlg, exchangeHash, blockSize, sharedSecret, letter, SessionId);

        /// <summary>
        /// RFC 4253 section 7.2 key derivation:
        /// <c>K1 = HASH(K || H || X || session_id)</c>,
        /// <c>K2 = HASH(K || H || K1)</c>,
        /// <c>Kn = HASH(K || H || K1 || ... || Kn-1)</c>.
        /// The concatenation of every previous hash block matters from the
        /// third block onwards; only using the immediately preceding block
        /// produces wrong keys for any future algorithm whose key material
        /// needs more than two hash outputs.
        /// </summary>
        internal static byte[] DeriveKey(KexAlgorithm kexAlg, byte[] exchangeHash, int keyLength, byte[] sharedSecret, char letter, byte[] sessionId)
        {
            var keyBuffer = new byte[keyLength];
            var keyBufferIndex = 0;
            byte[] previousHashes = null;

            while (keyBufferIndex < keyLength)
            {
                var writer = new SshDataWriter();
                // Hybrid PQ/T methods feed K into the KDF as an SSH string;
                // classical methods use the RFC 4253 mpint encoding.
                if (kexAlg.SharedSecretIsString)
                    writer.WriteBinary(sharedSecret);
                else
                    writer.WriteMpint(sharedSecret);
                writer.WriteBytes(exchangeHash);

                if (previousHashes == null)
                {
                    writer.Write((byte)letter);
                    writer.WriteBytes(sessionId);
                }
                else
                {
                    writer.WriteBytes(previousHashes);
                }

                var currentHash = kexAlg.ComputeHash(writer.ToByteArray());
                previousHashes = previousHashes == null
                    ? currentHash
                    : [.. previousHashes, .. currentHash];

                var copyLength = Math.Min(currentHash.Length, keyLength - keyBufferIndex);
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, copyLength);
                keyBufferIndex += copyLength;
            }

            return keyBuffer;
        }

        /// <summary>
        /// Compute the SSH packet MAC <c>seq || a || b</c> straight into
        /// <paramref name="destination"/> via the Span-based HMAC core
        /// (HmacAlgorithm.ComputeHash overload). Caller owns the destination
        /// - typically a stackalloc Span sized to DigestLength, so the
        /// per-packet MAC computation is now zero-allocation.
        /// </summary>
        private void ComputeHmac(HmacAlgorithm alg, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint seq, Span<byte> destination)
        {
            alg.ComputeHash(a, b, seq, destination);
        }

        /// <summary>
        /// Verify the inbound packet MAC <c>seq || a || b</c> against the
        /// received tag. Extracted as a synchronous helper so the stackalloc
        /// MAC buffer lives outside the async receive path (ref structs are
        /// not allowed across await points on C# 12).
        /// </summary>
        private bool VerifyHmac(HmacAlgorithm alg, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint seq, ReadOnlySpan<byte> expected)
        {
            Span<byte> mac = stackalloc byte[alg.DigestLength];
            ComputeHmac(alg, a, b, seq, mac);
            // Constant-time comparison: a byte-wise SequenceEqual leaks how
            // many leading MAC bytes matched, enabling a timing oracle.
            return CryptographicOperations.FixedTimeEquals(mac, expected);
        }

        internal SshService RegisterService(string serviceName, UserAuthArgs auth = null)
        {
            ArgumentNullException.ThrowIfNull(serviceName);

            SshService service = null;
            switch (serviceName)
            {
                case "ssh-userauth":
                    if (GetService<UserAuthService>() == null)
                        service = new UserAuthService(this);
                    break;
                case "ssh-connection":
                    if (auth != null && GetService<ConnectionService>() == null)
                        service = new ConnectionService(this, auth);
                    break;
            }
            if (service != null)
            {
                if (ServiceRegistered != null)
                    ServiceRegistered(this, service);

                _services.Add(service);
            }
            return service;
        }

        private class Algorithms : IDisposable
        {
            public KexAlgorithm KeyExchange;
            public PublicKeyAlgorithm PublicKey;
            public EncryptionAlgorithm ClientEncryption;
            public EncryptionAlgorithm ServerEncryption;
            public HmacAlgorithm ClientHmac;
            public HmacAlgorithm ServerHmac;
            public CompressionAlgorithm ClientCompression;
            public CompressionAlgorithm ServerCompression;
            public bool ClientHmacIsEtm;
            public bool ServerHmacIsEtm;
            private bool _disposed;

            public void Dispose()
            {
                if (_disposed)
                    return;
                _disposed = true;

                // KeyExchange/PublicKey are ephemeral handshake objects owned
                // and disposed by the KEX handler; only the per-session
                // cipher/MAC state belongs to this set.
                ClientEncryption?.Dispose();
                ServerEncryption?.Dispose();
                ClientHmac?.Dispose();
                ServerHmac?.Dispose();
                if (ClientCompression is IDisposable clientCompression)
                    clientCompression.Dispose();
                if (ServerCompression is IDisposable serverCompression)
                    serverCompression.Dispose();
            }
        }

        private class ExchangeContext
        {
            public string KeyExchange;
            public string PublicKey;
            public string ClientEncryption;
            public string ServerEncryption;
            public string ClientHmac;
            public string ServerHmac;
            public string ClientCompression;
            public string ServerCompression;

            public byte[] ClientKexInitPayload;
            public byte[] ServerKexInitPayload;

            public Algorithms NewAlgorithms;
        }
    }
}
