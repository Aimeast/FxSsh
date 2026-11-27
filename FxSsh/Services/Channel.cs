using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Logging;
using FxSsh.Messages.Connection;

namespace FxSsh.Services
{
    /// <summary>
    /// Base class for an SSH channel (RFC 4254 section 5): a flow-controlled,
    /// multiplexed data stream carried over a single SSH connection. Tracks
    /// the receive window and maximum packet size negotiated in each
    /// direction, enforces flow control on outbound data, and implements the
    /// channel lifecycle (open, EOF, close) for both sides. Concrete channel
    /// types such as <see cref="SessionChannel"/> derive from this class.
    /// </summary>
    public abstract class Channel
    {
        /// <summary>
        /// The connection service that owns this channel; used to send channel
        /// messages and to unregister the channel when it closes.
        /// </summary>
        protected ConnectionService _connectionService;
        private readonly object _windowLocker = new object();
        private bool _forceClosed;

        // Serializes whole SendData/SendDataAsync payloads so the chunks of
        // one logical write stay contiguous. Without it, two producers on the
        // same channel (e.g. an SFTP reply and a forwarded data pump) can
        // interleave chunks and corrupt both streams. Window waits happen
        // while the gate is held; nothing that runs on the SSH message loop
        // (OnConfirmed, ClientAdjustWindow, ForceClose) ever waits on it, so
        // a sender parked on a zero window cannot deadlock the loop.
        private readonly SemaphoreSlim _sendGate = new(1, 1);

        // Upper bound on bytes this channel may hold for a producer: the
        // whole payload while it is queued before OPEN_CONFIRMATION, and one
        // chunk at a time once the channel is confirmed (a direct send
        // streams from the caller's buffer, so only the chunk being framed
        // counts as buffered). This is a per-channel fairness sub-limit; the
        // session-wide byte budget additionally counts every reservation and
        // every framed packet, so a stalled peer stays bounded. Exceeding the
        // limit rejects the call instead of growing memory; hosts should
        // treat the exception as backpressure and stop the producer.
        private long _bufferedSendBytes;

        /// <summary>Gets the per-channel send-backlog cap from the session limits.</summary>
        internal int MaximumBufferedSendBytes
            => _connectionService._session.Limits.MaximumBufferedSendBytesPerChannel;

        /// <summary>Gets the bytes currently reserved by this channel's send backlog.</summary>
        public long BufferedSendBytes => System.Threading.Interlocked.Read(ref _bufferedSendBytes);

        // EOF/CLOSE requested on a server-initiated channel before the peer
        // confirmed it: defer them until the queued data has been flushed.
        private bool _pendingEof;
        private PendingClose _pendingClose;

        // Window signal shared by synchronous and asynchronous senders.
        // ClientAdjustWindow and ForceClose swap in a fresh TCS and complete
        // the old one so every waiter re-checks the window.
        private TaskCompletionSource<bool> _windowTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Number of senders currently parked in WaitForWindowAsync. The TCS
        // swap in ClientAdjustWindow/ForceClose is only needed when this is
        // non-zero; the common case (no sender waiting) then allocates no
        // TCS per WINDOW_ADJUST at all.
        private int _windowWaiters;

        /// <summary>
        /// Initializes a new instance of the <see cref="Channel"/> class for a
        /// client-initiated channel open, recording the receive window and
        /// maximum packet size the peer advertised (RFC 4254 section 5.1) and
        /// assigning this server's side the session's default local window and
        /// packet size.
        /// </summary>
        /// <param name="connectionService">The connection service that owns this channel.</param>
        /// <param name="clientChannelId">The channel identifier assigned by the client.</param>
        /// <param name="clientInitialWindowSize">The peer's initial receive window in bytes.</param>
        /// <param name="clientMaxPacketSize">The maximum packet size the peer accepts, in bytes.</param>
        /// <param name="serverChannelId">The channel identifier assigned by this server.</param>
        public Channel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId)
            : this(connectionService, clientChannelId, clientInitialWindowSize, clientMaxPacketSize,
                serverChannelId, allowZeroMaxPacket: false)
        {
        }

        /// <summary>
        /// Construct a server-initiated channel awaiting OPEN_CONFIRMATION.
        /// ClientChannelId is 0 until the peer confirms; outbound SendData
        /// calls are buffered until OnConfirmed resolves the peer channel.
        /// </summary>
        protected Channel(ConnectionService connectionService, uint serverChannelId)
            : this(connectionService, 0, 0, 0, serverChannelId, allowZeroMaxPacket: true)
        {
            PendingConfirmation = true;
        }

        private Channel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId, bool allowZeroMaxPacket)
        {
            ArgumentNullException.ThrowIfNull(connectionService);
            if (!allowZeroMaxPacket && clientMaxPacketSize == 0)
                throw new ArgumentOutOfRangeException(nameof(clientMaxPacketSize),
                    "A channel's maximum packet size must be greater than zero.");

            _connectionService = connectionService;

            ClientChannelId = clientChannelId;
            ClientInitialWindowSize = clientInitialWindowSize;
            ClientWindowSize = clientInitialWindowSize;
            ClientMaxPacketSize = clientMaxPacketSize;

            ServerChannelId = serverChannelId;
            ServerInitialWindowSize = Session.InitialLocalWindowSize;
            ServerWindowSize = Session.InitialLocalWindowSize;
            ServerMaxPacketSize = Session.LocalChannelDataPacketSize;
        }

        /// <summary>
        /// Resolve the peer channel after receiving OPEN_CONFIRMATION. Flushes
        /// any SendData bytes queued while pending. Safe to call once.
        /// </summary>
        internal void OnConfirmed(uint clientChannelId,
            uint peerInitialWindowSize, uint peerMaximumPacketSize)
        {
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Channel {ServerChannelId} open confirmed: peer window {peerInitialWindowSize}, max packet {peerMaximumPacketSize}.");
            if (!PendingConfirmation)
                return;

            TaskCompletionSource<bool> signal = null;
            lock (_windowLocker)
            {
                if (!PendingConfirmation)
                    return;

                // Publish the resolved peer window/ids BEFORE clearing the
                // pending flag: a concurrent SendData* must either observe the
                // pending flag (and queue its bytes) or observe the real
                // window - never a cleared flag with the constructor's zero
                // window, which would park the sender forever.
                ClientChannelId = clientChannelId;
                ClientInitialWindowSize = peerInitialWindowSize;
                ClientMaxPacketSize = peerMaximumPacketSize;
                ClientWindowSize = peerInitialWindowSize;
                PendingConfirmation = false;

                // Flush bytes produced while pending. Window credit is
                // reserved and the frames are enqueued while _windowLocker is
                // held, so a sender that wakes up after the confirmation
                // cannot overtake the queued bytes. Nothing in this helper
                // blocks: bytes that do not fit in the peer's initial window
                // stay queued for ClientAdjustWindow.
                FlushPendingSendsLocked();

                // A close/EOF requested while the channel was being opened
                // must follow the queued data, never precede it - including
                // the remainder FlushPendingSendsLocked could not fit into
                // the peer's initial window; ClientAdjustWindow fires it once
                // that remainder has been framed.
                if (_pendingSends.Count == 0)
                    SendPendingCloseOrEofLocked();

                // Wake every waiter parked on the zero window.
                if (_windowWaiters > 0)
                {
                    signal = _windowTcs;
                    _windowTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            signal?.TrySetResult(true);
        }

        /// <summary>Gets the channel identifier the client assigned to this channel (the peer's sender channel).</summary>
        public uint ClientChannelId { get; private set; }
        /// <summary>Gets the initial receive window the peer advertised at channel open, in bytes.</summary>
        public uint ClientInitialWindowSize { get; private set; }
        /// <summary>Gets the peer's remaining receive window in bytes; decremented by <see cref="SendData"/> and replenished when the peer sends SSH_MSG_CHANNEL_WINDOW_ADJUST.</summary>
        public uint ClientWindowSize { get; protected set; }
        /// <summary>Gets the maximum channel data packet size the peer accepts, in bytes.</summary>
        public uint ClientMaxPacketSize { get; private set; }

        /// <summary>Gets the channel identifier this server assigned to the channel (our sender channel).</summary>
        public uint ServerChannelId { get; private set; }
        /// <summary>Gets the initial local receive window advertised to the peer at channel open, in bytes.</summary>
        public uint ServerInitialWindowSize { get; private set; }
        /// <summary>Gets this side's remaining receive window in bytes, topped back up toward <see cref="ServerInitialWindowSize"/> by sending SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC 4254 section 5.2).</summary>
        public uint ServerWindowSize { get; protected set; }
        /// <summary>Gets the maximum channel data packet size this server accepts, in bytes.</summary>
        public uint ServerMaxPacketSize { get; private set; }

        private volatile bool _pendingConfirmation;
        /// <summary>
        /// True for a server-initiated channel awaiting OPEN_CONFIRMATION.
        /// Volatile: SendDataAsync on a pump thread reads this outside any
        /// lock while the session thread clears it in OnConfirmed - a stale
        /// read would send the caller to the direct path with an unresolved
        /// (zero) peer window.
        /// </summary>
        public bool PendingConfirmation { get => _pendingConfirmation; private set => _pendingConfirmation = value; }

        /// <summary>Queued outbound bytes produced before OPEN_CONFIRMATION arrives.</summary>
        private readonly System.Collections.Generic.List<ReadOnlyMemory<byte>> _pendingSends = [];

        /// <summary>Gets a value indicating whether the peer has sent SSH_MSG_CHANNEL_CLOSE.</summary>
        public bool ClientClosed { get; private set; }
        /// <summary>Gets a value indicating whether the peer has sent SSH_MSG_CHANNEL_EOF, meaning no more inbound data will arrive.</summary>
        public bool ClientMarkedEof { get; private set; }
        /// <summary>Gets a value indicating whether this server has sent SSH_MSG_CHANNEL_CLOSE.</summary>
        public bool ServerClosed { get; private set; }
        /// <summary>Gets a value indicating whether this server has sent SSH_MSG_CHANNEL_EOF.</summary>
        public bool ServerMarkedEof { get; private set; }
        /// <summary>
        /// Gets a value indicating whether the channel was force-closed (peer
        /// rejected the open, session teardown, or both sides closed). Reads
        /// the flag outside any lock, so a late reader may observe it one
        /// message-loop turn after the teardown.
        /// </summary>
        public bool IsForceClosed => _forceClosed;

        /// <summary>
        /// Occurs when channel data arrives from the peer (SSH_MSG_CHANNEL_DATA, RFC 4254 section 5.2).
        /// The payload memory is only valid for the duration of the handler:
        /// it is backed by a pooled buffer that the message loop recycles once
        /// dispatch finishes, so a handler that needs the bytes later must
        /// copy them.
        /// </summary>
        public event EventHandler<ReadOnlyMemory<byte>> DataReceived;
        /// <summary>
        /// Ownership-aware variant of <see cref="DataReceived"/> used by the
        /// in-library forwarding bridge and SFTP engine. Fires before the
        /// public event while the lease is still valid; subscribers call
        /// <see cref="ChannelDataLease.TryRetainOrCopy"/> to take ownership.
        /// </summary>
        internal event EventHandler<ChannelDataLease> LeaseReceived;
        /// <summary>Occurs when the peer marks its side of the stream closed with SSH_MSG_CHANNEL_EOF.</summary>
        public event EventHandler EofReceived;
        /// <summary>Occurs when the peer closes the channel with SSH_MSG_CHANNEL_CLOSE; the channel is torn down once both sides have closed.</summary>
        public event EventHandler CloseReceived;
        /// <summary>Occurs when the peer resizes the terminal with a "window-change" channel request (RFC 4254 section 6.7).</summary>
        public event EventHandler<WindowChangeArgs> WindowChange;

        /// <summary>
        /// Raised exactly once when the channel is force-closed (peer rejected
        /// the open, session teardown, or both sides closed). Bridges that
        /// hold external resources (e.g. a forwarded TCP socket or a terminal)
        /// must release them when this fires - no CHANNEL_CLOSE exchange will
        /// follow.
        /// </summary>
        public event EventHandler ForceClosed;

        /// <summary>
        /// Sends the supplied bytes to the peer as SSH_MSG_CHANNEL_DATA
        /// (RFC 4254 section 5.2), splitting them into chunks that respect
        /// both the peer's remaining flow-control window and its maximum
        /// packet size. Blocks while the peer's window is exhausted until a
        /// SSH_MSG_CHANNEL_WINDOW_ADJUST arrives; throws
        /// <see cref="ObjectDisposedException"/> if the channel is force-closed
        /// while blocked. Whole calls are serialized, so chunks from
        /// concurrent senders are never interleaved.
        /// </summary>
        /// <param name="data">
        /// The payload to send. On a channel still awaiting
        /// OPEN_CONFIRMATION the bytes are copied and queued, so the caller
        /// may recycle the buffer as soon as this method returns.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// Queueing the payload on a channel that still awaits
        /// OPEN_CONFIRMATION would exceed its send-backlog bound; the caller
        /// should treat this as backpressure and stop producing.
        /// </exception>
        public void SendData(ReadOnlyMemory<byte> data)
            => SendDataCoreAsync(data, CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>
        /// Async equivalent of <see cref="SendData"/> for use from async pumps
        /// (e.g. PortForwardingService bridges). When the peer's receive window
        /// is exhausted it awaits the window signal instead of blocking a
        /// thread; the chunking, window accounting and serialization are
        /// identical to the synchronous path.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Queueing the payload on a channel that still awaits
        /// OPEN_CONFIRMATION would exceed its send-backlog bound; the caller
        /// should treat this as backpressure and stop producing.
        /// </exception>
        public Task SendDataAsync(ReadOnlyMemory<byte> data)
            => SendDataCoreAsync(data, CancellationToken.None).AsTask();

        private async ValueTask SendDataCoreAsync(ReadOnlyMemory<byte> data, CancellationToken token)
        {
            if (data.Length == 0)
                return;

            await _sendGate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                lock (_windowLocker)
                {
                    if (_forceClosed)
                        throw new ObjectDisposedException(nameof(Channel));

                    if (PendingConfirmation)
                    {
                        // The whole payload is copied into the pre-confirmation
                        // backlog, so it is reserved as a whole: a call larger
                        // than the backlog cap is rejected up front instead of
                        // queuing unbounded bytes. The queue releases the
                        // reservation as it flushes (or on force close).
                        if (!TryReserveBufferedBytes(data.Length))
                            ThrowBufferedSendOverflow();
                        _pendingSends.Add(data.ToArray());
                        if (Log.IsEnabled(LogLevel.Trace))
                            Log.Trace($"SendData queued: channel={ServerChannelId} len={data.Length}.");
                        return;
                    }
                }

                var total = (uint)data.Length;
                var offset = 0;
                while (total > 0)
                {
                    if (Log.IsEnabled(LogLevel.Trace) && ClientWindowSize == 0)
                        Log.Trace($"SendData parked on channel {ServerChannelId}: peer window exhausted.");

                    var packetSize = await ReserveWindowAsync(total).ConfigureAwait(false);

                    // Reserve credit one chunk at a time: a direct send
                    // streams from the caller's buffer, so a call larger than
                    // the cap flows through a healthy window instead of
                    // failing up front - only the chunk being framed is held
                    // by the channel.
                    if (!TryReserveBufferedBytes((int)packetSize))
                        ThrowBufferedSendOverflow();
                    try
                    {
                        SendChunk(data.Slice(offset, (int)packetSize));
                    }
                    finally
                    {
                        ReleaseBufferedBytes((int)packetSize);
                    }

                    total -= packetSize;
                    offset += (int)packetSize;
                }
            }
            finally
            {
                _sendGate.Release();
            }
        }

        /// <summary>
        /// Reserve channel send-backlog credit for <paramref name="length"/>
        /// bytes. The per-channel cap is a fairness sub-limit inside the
        /// session-wide outbound budget; both must accept the reservation.
        /// </summary>
        private bool TryReserveBufferedBytes(int length)
        {
            var total = System.Threading.Interlocked.Add(ref _bufferedSendBytes, length);
            if (total <= MaximumBufferedSendBytes
                && _connectionService._session.TryReserveOutboundBuffer(length))
                return true;

            System.Threading.Interlocked.Add(ref _bufferedSendBytes, -length);
            return false;
        }

        private void ReleaseBufferedBytes(int length)
        {
            System.Threading.Interlocked.Add(ref _bufferedSendBytes, -length);
            _connectionService._session.ReleaseOutboundBuffer(length);
        }

        private void ThrowBufferedSendOverflow()
            => throw new InvalidOperationException(
                string.Format("Channel {0} send backlog exceeds {1} bytes; the peer is not consuming data.", ServerChannelId, MaximumBufferedSendBytes));

        /// <summary>
        /// Reserve window credit for one chunk, awaiting the window signal
        /// until the peer adjusts its window. Callers hold
        /// <see cref="_sendGate"/>; the synchronous <see cref="SendData"/>
        /// wrapper blocks on the same signal.
        /// </summary>
        private async ValueTask<uint> ReserveWindowAsync(uint requested)
        {
            while (true)
            {
                lock (_windowLocker)
                {
                    if (_forceClosed)
                        throw new ObjectDisposedException(nameof(Channel));

                    var packetSize = Math.Min(Math.Min(ClientWindowSize, EffectiveMaxPacketSize), requested);
                    if (packetSize > 0)
                    {
                        ClientWindowSize -= packetSize;
                        return packetSize;
                    }
                }

                await WaitForWindowAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// The peer's maximum packet size capped by the library's own
        /// data-packet size: a peer advertising 4 GiB must not make the server
        /// frame and queue megabytes in a single SSH packet (which would also
        /// exceed this library's own 35 KB receive limit and many clients'
        /// limits). ConnectionService rejects a zero value at open time.
        /// </summary>
        private uint EffectiveMaxPacketSize
        {
            get
            {
                Debug.Assert(ClientMaxPacketSize > 0, "OPEN_CONFIRMATION must publish a positive maximum packet size.");
                return Math.Min(ClientMaxPacketSize, (uint)Session.LocalChannelDataPacketSize);
            }
        }

        private void SendChunk(ReadOnlyMemory<byte> chunk)
        {
            // Fresh message per chunk: Session.SendMessage may hold the
            // message by reference in _blockedMessages during rekey, so a
            // shared instance would alias and corrupt every queued chunk.
            _connectionService._session.SendMessage(new ChannelDataMessage
            {
                RecipientChannel = ClientChannelId,
                Data = chunk,
            });
        }

        /// <summary>
        /// Flush the pre-confirmation backlog without ever blocking: window
        /// credit is reserved under <see cref="_windowLocker"/> and chunks are
        /// enqueued immediately. Bytes that do not fit in the current window
        /// stay queued (or have their remainder requeued) and are sent by the
        /// next <see cref="ClientAdjustWindow"/>.
        /// </summary>
        private void FlushPendingSendsLocked()
        {
            if (_pendingSends.Count == 0)
                return;

            if (Log.IsEnabled(LogLevel.Debug))
                Log.Debug($"Channel {ServerChannelId} confirmed; flushing {_pendingSends.Count} buffered chunks.");

            System.Collections.Generic.List<ReadOnlyMemory<byte>> remaining = null;
            var releasedBytes = 0;
            foreach (var buffered in _pendingSends)
            {
                var offset = 0;
                while (offset < buffered.Length)
                {
                    var packetSize = Math.Min(
                        (uint)(buffered.Length - offset),
                        Math.Min(ClientWindowSize, EffectiveMaxPacketSize));
                    if (packetSize == 0)
                    {
                        (remaining ??= []).Add(buffered.Slice(offset));
                        break;
                    }

                    ClientWindowSize -= packetSize;
                    SendChunk(buffered.Slice(offset, (int)packetSize));
                    releasedBytes += (int)packetSize;
                    offset += (int)packetSize;
                }
            }

            _pendingSends.Clear();
            if (remaining != null)
                _pendingSends.AddRange(remaining);

            // Release the reservations for the prefix that actually went out
            // only after the whole flush succeeded. If a SendChunk throws
            // mid-loop, _pendingSends still holds the original buffers and
            // ForceClose releases their full lengths exactly once.
            ReleaseBufferedBytes(releasedBytes);
        }

        /// <summary>
        /// Fire a close/EOF that was deferred behind queued data. The caller
        /// holds <see cref="_windowLocker"/> and <see cref="_pendingSends"/>
        /// is empty, so the deferred message can never precede those bytes on
        /// the wire.
        /// </summary>
        private void SendPendingCloseOrEofLocked()
        {
            if (_pendingClose is { } pendingClose)
            {
                ServerClosed = true;
                if (pendingClose.SignalName != null)
                {
                    SendSignalCloseCore(pendingClose.SignalName, pendingClose.CoreDumped,
                        pendingClose.ErrorMessage, pendingClose.Language);
                }
                else
                {
                    SendCloseCore(pendingClose.ExitCode);
                }
            }
            else if (_pendingEof)
            {
                SendEofCore();
            }
        }

        /// <summary>
        /// Await the peer's receive window to reopen. Returns when
        /// ClientWindowSize &gt; 0 or throws ObjectDisposedException after the
        /// channel was force-closed (matching the synchronous SendData
        /// teardown semantics).
        /// </summary>
        private async ValueTask WaitForWindowAsync()
        {
            while (true)
            {
                TaskCompletionSource<bool> signal;
                lock (_windowLocker)
                {
                    if (ClientWindowSize > 0)
                        return;
                    if (_forceClosed)
                        throw new ObjectDisposedException(nameof(Channel));
                    _windowWaiters++;
                    signal = _windowTcs;
                }
                try
                {
                    await signal.Task.ConfigureAwait(false);
                }
                finally
                {
                    lock (_windowLocker)
                        _windowWaiters--;
                }
                // Spurious wake-ups are safe: loop and re-evaluate the window.
            }
        }

        /// <summary>
        /// Sends SSH_MSG_CHANNEL_EOF (RFC 4254 section 5.3) to tell the peer
        /// that no more data will be written to this channel. Has no effect
        /// once this server has already marked EOF or the channel was
        /// force-closed: the peer has already removed a rejected channel,
        /// and newer OpenSSH clients answer packets for a nonexistent
        /// channel with a protocol-error disconnect.
        /// </summary>
        public void SendEof()
            => SendEofCoreAsync(CancellationToken.None).GetAwaiter().GetResult();

        /// <summary>
        /// Sends SSH_MSG_CHANNEL_EOF after waiting for the send gate, so any
        /// SendData/SendDataAsync call that is in progress (or already queued
        /// on the gate) has framed its chunks first. Use this when a producer
        /// and the EOF are driven by different tasks (e.g. terminal output
        /// followed by the shell exit notification).
        /// </summary>
        /// <param name="cancellationToken">Cancels the wait for in-flight sends.</param>
        public Task SendEofAsync(CancellationToken cancellationToken = default)
            => SendEofCoreAsync(cancellationToken).AsTask();

        private async ValueTask SendEofCoreAsync(CancellationToken cancellationToken)
        {
            await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                lock (_windowLocker)
                {
                    if (_forceClosed || ServerMarkedEof)
                        return;

                    if (PendingConfirmation || _pendingSends.Count > 0)
                    {
                        // Do not overtake bytes that are still queued: the
                        // pre-confirmation backlog, or the remainder waiting
                        // for peer window credit after confirmation.
                        _pendingEof = true;
                        return;
                    }

                    SendEofCore();
                }
            }
            finally
            {
                _sendGate.Release();
            }
        }

        private void SendEofCore()
        {
            ServerMarkedEof = true;
            _connectionService._session.SendMessage(new ChannelEofMessage { RecipientChannel = ClientChannelId });
        }

        /// <summary>
        /// Closes the channel by sending SSH_MSG_CHANNEL_CLOSE (RFC 4254
        /// section 5.3), optionally preceded by an "exit-status" channel
        /// request reporting the command's exit code (RFC 4254 section 6.10).
        /// Has no effect once this server has already closed the channel.
        /// </summary>
        /// <param name="exitCode">Optional exit code to report as "exit-status" before the close.</param>
        public void SendClose(uint? exitCode = null)
            => SendCloseCoreAsync(exitCode, CancellationToken.None).GetAwaiter().GetResult();

        private void SendCloseCore(uint? exitCode)
        {
            if (exitCode.HasValue)
                _connectionService._session.SendMessage(new ExitStatusMessage { RecipientChannel = ClientChannelId, ExitStatus = exitCode.Value });
            _connectionService._session.SendMessage(new ChannelCloseMessage { RecipientChannel = ClientChannelId });

            CheckBothClosed();
        }

        /// <summary>
        /// Sends SSH_MSG_CHANNEL_CLOSE (with an optional exit-status first)
        /// after waiting for the send gate, so the close cannot overtake data
        /// still being framed by another producer. Subject to the same
        /// pre-confirmation deferral as <see cref="SendClose"/>.
        /// </summary>
        /// <param name="exitCode">Optional exit status to report before the close.</param>
        /// <param name="cancellationToken">Cancels the wait for in-flight sends.</param>
        public Task SendCloseAsync(uint? exitCode = null, CancellationToken cancellationToken = default)
            => SendCloseCoreAsync(exitCode, cancellationToken).AsTask();

        private async ValueTask SendCloseCoreAsync(uint? exitCode, CancellationToken cancellationToken)
        {
            await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                lock (_windowLocker)
                {
                    if (_forceClosed || ServerClosed)
                        return;

                    if (PendingConfirmation || _pendingSends.Count > 0)
                    {
                        // Defer until every queued byte has been framed, so
                        // CLOSE never precedes data the peer has not seen:
                        // the pre-confirmation backlog, or the remainder
                        // waiting for peer window credit after confirmation.
                        _pendingClose ??= PendingClose.ForExitStatus(exitCode);
                        return;
                    }

                    ServerClosed = true;
                }

                SendCloseCore(exitCode);
            }
            finally
            {
                _sendGate.Release();
            }
        }

        /// <summary>
        /// Close the channel after the process was terminated by a signal,
        /// emitting an "exit-signal" channel request (RFC 4254 section 6.10) before
        /// SSH_MSG_CHANNEL_CLOSE. Mutually exclusive with SendClose(exitCode):
        /// a channel reports EITHER exit-status OR exit-signal, never both.
        /// </summary>
        /// <param name="signalName">Signal name WITHOUT "SIG" prefix (e.g. "TERM", "KILL", "SEGV").</param>
        /// <param name="coreDumped">Whether the process produced a core dump.</param>
        /// <param name="errorMessage">Human-readable explanation (may be empty).</param>
        /// <param name="language">Language tag per RFC 3066 (defaults to "en").</param>
        public void SendSignalClose(string signalName, bool coreDumped = false, string errorMessage = "", string language = "en")
            => SendSignalCloseCoreAsync(signalName, coreDumped, errorMessage, language, CancellationToken.None)
                .GetAwaiter().GetResult();

        /// <summary>
        /// Async variant of <see cref="SendSignalClose"/>. Waits for the send
        /// gate so the exit-signal cannot overtake data still being framed by
        /// another producer.
        /// </summary>
        public Task SendSignalCloseAsync(string signalName, bool coreDumped = false,
            string errorMessage = "", string language = "en", CancellationToken cancellationToken = default)
            => SendSignalCloseCoreAsync(signalName, coreDumped, errorMessage, language, cancellationToken)
                .AsTask();

        private async ValueTask SendSignalCloseCoreAsync(string signalName, bool coreDumped,
            string errorMessage, string language, CancellationToken cancellationToken)
        {
            await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                lock (_windowLocker)
                {
                    if (_forceClosed || ServerClosed)
                        return;

                    if (PendingConfirmation || _pendingSends.Count > 0)
                    {
                        // Same deferral as SendCloseCoreAsync: the exit-signal
                        // must not precede data that is still queued.
                        _pendingClose ??= PendingClose.ForSignal(signalName, coreDumped, errorMessage, language);
                        return;
                    }

                    ServerClosed = true;
                }

                SendSignalCloseCore(signalName, coreDumped, errorMessage, language);
            }
            finally
            {
                _sendGate.Release();
            }
        }

        private void SendSignalCloseCore(string signalName, bool coreDumped, string errorMessage, string language)
        {
            _connectionService._session.SendMessage(new ExitSignalMessage
            {
                RecipientChannel = ClientChannelId,
                SignalName = signalName ?? string.Empty,
                CoreDumped = coreDumped,
                ErrorMessage = errorMessage ?? string.Empty,
                Language = language ?? "en",
            });
            _connectionService._session.SendMessage(new ChannelCloseMessage { RecipientChannel = ClientChannelId });

            CheckBothClosed();
        }

        internal void OnData(ReadOnlyMemory<byte> data)
            => OnData(ChannelDataLease.Wrap(data));

        internal void OnData(ChannelDataLease lease)
        {
            var data = lease.Memory;
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Channel {ServerChannelId} received {data.Length} bytes.");

            // RFC 4254 section 5.2: the peer must not exceed the maximum
            // packet size or the receive window it was granted. Both are
            // enforced before the payload reaches any service.
            if (data.Length > ServerMaxPacketSize)
            {
                throw new SshConnectionException(
                    string.Format("Channel data packet of {0} bytes exceeds the maximum of {1}.", data.Length, ServerMaxPacketSize),
                    DisconnectReason.ProtocolError);
            }
            ServerAttemptAdjustWindow((uint)data.Length);

            LeaseReceived?.Invoke(this, lease);
            DataReceived?.Invoke(this, data);
        }

        internal void OnEof()
        {
            Log.Debug($"Channel {ServerChannelId} EOF received.");
            ClientMarkedEof = true;

            EofReceived?.Invoke(this, EventArgs.Empty);
        }

        internal void OnClose()
        {
            Log.Debug($"Channel {ServerChannelId} close received.");
            ClientClosed = true;

            CloseReceived?.Invoke(this, EventArgs.Empty);

            CheckBothClosed();
        }

        internal void OnWindowChange(WindowChangeArgs args)
        {
            WindowChange?.Invoke(this, args);
        }

        internal void ClientAdjustWindow(uint bytesToAdd)
        {
            TaskCompletionSource<bool> signal = null;
            lock (_windowLocker)
            {
                // Saturate instead of wrapping: a malicious/huge adjust must
                // not reset the credit to a tiny value via uint overflow.
                ClientWindowSize = (uint)Math.Min(uint.MaxValue, (ulong)ClientWindowSize + bytesToAdd);

                // Queued bytes from before confirmation have priority over
                // any sender that is waiting for this credit.
                if (_pendingSends.Count > 0)
                    FlushPendingSendsLocked();

                // The backlog is gone: a close/EOF deferred behind it -
                // requested before confirmation, or while a remainder was
                // waiting for window credit - follows the last queued byte.
                if (_pendingSends.Count == 0)
                    SendPendingCloseOrEofLocked();

                // Wake every sender parked in WaitForWindowAsync. Swap in a
                // fresh TCS and complete the old one so every waiter re-checks
                // the window - but only when there IS a waiter. The common
                // case (a sender whose window never drained) then allocates no
                // TCS per WINDOW_ADJUST.
                if (_windowWaiters > 0)
                {
                    signal = _windowTcs;
                    _windowTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            signal?.TrySetResult(true);
        }

        private void ServerAttemptAdjustWindow(uint messageLength)
        {
            if (messageLength > ServerWindowSize)
            {
                // RFC 4254 section 5.2: data beyond the advertised receive
                // window is a protocol violation; letting the subtraction wrap
                // would hand the peer a huge window.
                throw new SshConnectionException(
                    string.Format("Channel data of {0} bytes exceeds the remaining window of {1}.", messageLength, ServerWindowSize),
                    DisconnectReason.ProtocolError);
            }

            ServerWindowSize -= messageLength;

            // RFC 4254 section 5.2: the local window advertised to the peer is topped
            // up by sending SSH_MSG_CHANNEL_WINDOW_ADJUST before the peer's send
            // window would otherwise stall. The exact refresh point is an
            // implementation choice; the only hard constraint is that the peer
            // must always have at least one maximum-sized packet worth of credit
            // available until EOF (otherwise it blocks mid-transfer).
            //
            // We refresh when the remaining window drops below HALF of the
            // initial window rather than below one max-packet (ServerMaxPacketSize).
            // With InitialLocalWindowSize = 2 MiB and ServerMaxPacketSize = 32 KiB,
            // the previous "<= ServerMaxPacketSize" threshold refreshed roughly
            // every 128 inbound ~16 KiB packets; the half-window threshold refreshes
            // roughly every 64 packets, which halves how often the SSH receive
            // thread is synchronously interrupted to encrypt + transmit a
            // WINDOW_ADJUST message. Because 1/2 initial (1 MiB) is still far
            // above ServerMaxPacketSize (32 KiB), the peer can always send a
            // full-size packet between refreshes - the RFC 4254 hard constraint
            // stays satisfied. BytesToAdd tops the window back up to the initial
            // size, matching the RFC's "top up" semantics.
            if (ServerWindowSize < ServerInitialWindowSize / 2)
            {
                _connectionService._session.SendMessage(new ChannelWindowAdjustMessage
                {
                    RecipientChannel = ClientChannelId,
                    BytesToAdd = ServerInitialWindowSize - ServerWindowSize
                });
                ServerWindowSize = ServerInitialWindowSize;
            }
        }

        private void CheckBothClosed()
        {
            if (ClientClosed && ServerClosed)
            {
                ForceClose();
            }
        }

        internal void ForceClose()
        {
            // ForceClose can be reached more than once: SendClose() drives it
            // when the server side closes first, and OnClose() drives it again
            // when the client's CHANNEL_CLOSE arrives (or vice versa), plus
            // any external listener wired onto CloseReceived can re-enter it.
            // Guard with a flag so teardown happens exactly once.
            TaskCompletionSource<bool> signal = null;
            lock (_windowLocker)
            {
                if (_forceClosed)
                    return;
                _forceClosed = true;
                // Nothing queued before confirmation can be delivered anymore;
                // release the payload copies and their backlog reservations
                // promptly.
                foreach (var pending in _pendingSends)
                    ReleaseBufferedBytes(pending.Length);
                _pendingSends.Clear();

                // Wake every sender parked in WaitForWindowAsync; it re-checks
                // _forceClosed and throws ObjectDisposedException, matching the
                // previous "waiting on a closed handle" semantics.
                if (_windowWaiters > 0)
                {
                    signal = _windowTcs;
                    _windowTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            signal?.TrySetResult(true);

            // ForceClosed handlers are host/bridge code (SFTP teardown,
            // forwarded-socket release): one throwing subscriber must not
            // skip the remaining subscribers or the RemoveChannel call below,
            // which would leave a closed channel registered for the rest of
            // the session and leak the resources the other subscribers hold.
            var forceClosed = ForceClosed;
            if (forceClosed != null)
            {
                foreach (var handler in forceClosed.GetInvocationList())
                {
                    try { ((EventHandler)handler)(this, EventArgs.Empty); }
                    catch (Exception ex) { Log.Warn($"Channel {ServerChannelId} ForceClosed handler failed: {ex.Message}"); }
                }
            }

            _connectionService.RemoveChannel(this);
        }

        /// <summary>
        /// A close requested before OPEN_CONFIRMATION, carrying either an
        /// exit-status or an exit-signal. Stored as one deferred action so the
        /// pending state cannot hold contradictory fields.
        /// </summary>
        private sealed class PendingClose
        {
            public uint? ExitCode { get; private init; }
            public string SignalName { get; private init; }
            public bool CoreDumped { get; private init; }
            public string ErrorMessage { get; private init; }
            public string Language { get; private init; }

            public static PendingClose ForExitStatus(uint? exitCode)
                => new() { ExitCode = exitCode };

            public static PendingClose ForSignal(string signalName, bool coreDumped,
                string errorMessage, string language)
                => new()
                {
                    SignalName = signalName ?? string.Empty,
                    CoreDumped = coreDumped,
                    ErrorMessage = errorMessage ?? string.Empty,
                    Language = language ?? "en",
                };
        }
    }
}
