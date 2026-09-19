using System;
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

        // Async window signal for SendDataAsync. ClientAdjustWindow and
        // ForceClose swap in a fresh TCS and complete the old one so every
        // awaiting sender re-checks the window; the synchronous SendData
        // waiters are woken by the Monitor.PulseAll under the same lock.
        private TaskCompletionSource<bool> _windowTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Number of senders currently parked in WaitForWindowAsync. The TCS
        // swap in ClientAdjustWindow/ForceClose is only needed when this is
        // non-zero; the common case (no async sender waiting) then allocates
        // no TCS per WINDOW_ADJUST at all.
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
        {
            ArgumentNullException.ThrowIfNull(connectionService);

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
        /// Construct a server-initiated channel awaiting OPEN_CONFIRMATION.
        /// ClientChannelId is 0 until the peer confirms; outbound SendData
        /// calls are buffered until OnConfirmed resolves the peer channel.
        /// </summary>
        protected Channel(ConnectionService connectionService, uint serverChannelId)
            : this(connectionService, 0, 0, 0, serverChannelId)
        {
            PendingConfirmation = true;
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

            // Publish the resolved peer window/ids BEFORE clearing the pending
            // flag: a concurrent SendData* must either observe the pending flag
            // (and queue its bytes) or observe the real window - never a
            // cleared flag with the constructor's zero window, which would
            // park the sender on the window condition forever.
            ClientChannelId = clientChannelId;
            ClientInitialWindowSize = peerInitialWindowSize;
            ClientMaxPacketSize = peerMaximumPacketSize;
            PeerInitialWindowSize = peerInitialWindowSize;
            PeerMaximumPacketSize = peerMaximumPacketSize;

            lock (_windowLocker)
            {
                ClientWindowSize = peerInitialWindowSize;
                PendingConfirmation = false;

                // Wake any sender that already parked on the zero window -
                // BOTH kinds: Monitor.Wait (synchronous SendData) via
                // PulseAll, and the async WaitForWindowAsync TCS waiters.
                Monitor.PulseAll(_windowLocker);
                TaskCompletionSource<bool> signal = null;
                if (_windowWaiters > 0)
                {
                    signal = _windowTcs;
                    _windowTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }

                // Flush bytes produced while pending (in arrival order).
                // SendData re-enters _windowLocker (Monitor is reentrant) and
                // sends directly now that the flag is cleared.
                if (_pendingSends.Count > 0)
                {
                    if (Log.IsEnabled(LogLevel.Debug))
                        Log.Debug($"Channel {ServerChannelId} confirmed; flushing {_pendingSends.Count} buffered chunks.");
                    foreach (var chunk in _pendingSends)
                        SendData(chunk);
                    _pendingSends.Clear();
                }

                signal?.TrySetResult(true);
            }
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

        /// <summary>Window advertised by the peer once OPEN_CONFIRMATION arrives; 0 until then.</summary>
        public uint PeerInitialWindowSize { get; private set; }
        /// <summary>Maximum packet size the peer accepts once OPEN_CONFIRMATION arrives; 0 until then.</summary>
        public uint PeerMaximumPacketSize { get; private set; }

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

        /// <summary>Occurs when channel data arrives from the peer (SSH_MSG_CHANNEL_DATA, RFC 4254 section 5.2).</summary>
        public event EventHandler<ReadOnlyMemory<byte>> DataReceived;
        /// <summary>Occurs when the peer marks its side of the stream closed with SSH_MSG_CHANNEL_EOF.</summary>
        public event EventHandler EofReceived;
        /// <summary>Occurs when the peer closes the channel with SSH_MSG_CHANNEL_CLOSE; the channel is torn down once both sides have closed.</summary>
        public event EventHandler CloseReceived;
        /// <summary>Occurs when the peer resizes the terminal with a "window-change" channel request (RFC 4254 section 6.7).</summary>
        public event EventHandler<WindowChangeArgs> WindowChange;

        /// <summary>
        /// Sends the supplied bytes to the peer as SSH_MSG_CHANNEL_DATA
        /// (RFC 4254 section 5.2), splitting them into chunks that respect
        /// both the peer's remaining flow-control window and its maximum
        /// packet size. Blocks while the peer's window is exhausted until a
        /// SSH_MSG_CHANNEL_WINDOW_ADJUST arrives; throws
        /// <see cref="ObjectDisposedException"/> if the channel is force-closed
        /// while blocked.
        /// </summary>
        /// <param name="data">
        /// The payload to send. The buffer is not copied; on a channel still
        /// awaiting OPEN_CONFIRMATION the bytes are queued, so the caller must
        /// keep the underlying buffer valid.
        /// </param>
        public void SendData(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0)
            {
                return;
            }

            // Server-initiated channels buffer outbound bytes until the peer's
            // OPEN_CONFIRMATION resolves ClientChannelId and the peer window.
            // The check-and-queue is atomic with OnConfirmed's flag clear
            // (both under _windowLocker): a sender must never fall through to
            // the direct path while the peer window is still unresolved.
            // Slice the caller's memory instead of Clone() - ReadOnlyMemory<byte>
            // is a by-value view over the caller's buffer, safe to retain only
            // if the caller guarantees the buffer outlives the flush. Downstream
            // services hand us bytes they themselves own for the channel's
            // lifetime (terminal pipes, tcp sockets, sftp), so a slice here is
            // safe without a copy.
            lock (_windowLocker)
            {
                if (PendingConfirmation)
                {
                    _pendingSends.Add(data);
                    return;
                }
            }

            // Fresh message per chunk: Session.SendMessage may hold the
            // message by reference in _blockedMessages during rekey, so a
            // shared instance would alias and corrupt every queued chunk.
            var msg = new ChannelDataMessage();
            msg.RecipientChannel = ClientChannelId;

            var total = (uint)data.Length;
            var offset = 0L;
            do
            {
                uint packetSize;
                lock (_windowLocker)
                {
                    packetSize = Math.Min(Math.Min(ClientWindowSize, ClientMaxPacketSize), total);
                    if (packetSize > 0)
                    {
                        ClientWindowSize -= packetSize;
                    }
                    else
                    {
                        // Peer's receive window is exhausted. Park on a Monitor
                        // condition variable instead of the old
                        // EventWaitHandle Set/Thread.Sleep(1)/Reset pulse:
                        // the sleep ran on the ConnectionService message loop
                        // (the single SSH receive thread) and capped throughput
                        // at ~1000 packets/sec under sustained load. Monitor.Wait
                        // releases the lock; ClientAdjustWindow PulseAll's the
                        // moment the peer's WINDOW_ADJUST arrives, and
                        // ForceClose PulseAll's to unblock us during teardown.
                        // Re-check _forceClosed to keep the old "waiting on a
                        // disposed handle throws" teardown semantics.
                        Monitor.Wait(_windowLocker);
                        if (_forceClosed)
                            throw new ObjectDisposedException(nameof(Channel));
                        // Window may still be 0 after a spurious wake; loop
                        // around and re-evaluate packetSize.
                        continue;
                    }
                }

                // Zero-copy slice: ChannelDataMessage.Data is now a
                // ReadOnlyMemory<byte>, so framing the per-packet chunk is just
                // a view over the caller's buffer - no new byte[packetSize]
                // and no Array.Copy per chunk (was the E hot-path allocation).
                msg.Data = data.Slice((int)offset, (int)packetSize);
                _connectionService._session.SendMessage(msg);

                total -= packetSize;
                offset += packetSize;
            } while (total > 0);
        }

        /// <summary>
        /// Async equivalent of <see cref="SendData"/> for use from async pumps
        /// (e.g. PortForwardingService bridges). When the peer's receive window
        /// is exhausted it awaits the window signal instead of blocking a
        /// thread in Monitor.Wait; the chunking, window accounting and
        /// zero-copy slicing are identical to the synchronous path.
        /// </summary>
        public async Task SendDataAsync(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0)
            {
                return;
            }

            // Same buffering semantics as SendData: server-initiated channels
            // buffer outbound bytes until the peer's OPEN_CONFIRMATION. The
            // check-and-queue is atomic with OnConfirmed's flag clear (both
            // under _windowLocker) so a sender never falls through to the
            // direct path while the peer window is still unresolved.
            lock (_windowLocker)
            {
                if (PendingConfirmation)
                {
                    _pendingSends.Add(data);
                    if (Log.IsEnabled(LogLevel.Trace))
                        Log.Trace($"SendDataAsync queued: channel={ServerChannelId} len={data.Length}.");
                    return;
                }
            }

            // Fresh message per chunk: Session.SendMessage may hold the
            // message by reference in _blockedMessages during rekey, so a
            // shared instance would alias and corrupt every queued chunk.
            var msg = new ChannelDataMessage();
            msg.RecipientChannel = ClientChannelId;

            var total = (uint)data.Length;
            var offset = 0L;
            while (total > 0)
            {
                uint packetSize;
                lock (_windowLocker)
                {
                    packetSize = Math.Min(Math.Min(ClientWindowSize, ClientMaxPacketSize), total);
                    if (packetSize > 0)
                    {
                        ClientWindowSize -= packetSize;
                    }
                }

                if (packetSize == 0)
                {
                    // Peer's receive window is exhausted. Await the window
                    // signal (completed by ClientAdjustWindow / ForceClose)
                    // instead of Monitor.Wait, so no thread is blocked. The
                    // loop re-checks the window after every wake-up, exactly
                    // like the synchronous path re-evaluates after PulseAll.
                    if (Log.IsEnabled(LogLevel.Trace))
                        Log.Trace($"SendDataAsync parked on channel {ServerChannelId}: peer window exhausted ({ClientWindowSize} bytes left).");
                    await WaitForWindowAsync();
                    continue;
                }

                // Zero-copy slice: same framing as SendData.
                msg.Data = data.Slice((int)offset, (int)packetSize);
                _connectionService._session.SendMessage(msg);

                total -= packetSize;
                offset += packetSize;
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
                    await signal.Task;
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
        /// once this server has already marked EOF.
        /// </summary>
        public void SendEof()
        {
            if (ServerMarkedEof)
                return;

            ServerMarkedEof = true;
            var msg = new ChannelEofMessage { RecipientChannel = ClientChannelId };
            _connectionService._session.SendMessage(msg);
        }

        /// <summary>
        /// Closes the channel by sending SSH_MSG_CHANNEL_CLOSE (RFC 4254
        /// section 5.3), optionally preceded by an "exit-status" channel
        /// request reporting the command's exit code (RFC 4254 section 6.10).
        /// Has no effect once this server has already closed the channel.
        /// </summary>
        /// <param name="exitCode">Optional exit code to report as "exit-status" before the close.</param>
        public void SendClose(uint? exitCode = null)
        {
            if (ServerClosed)
                return;

            ServerClosed = true;
            if (exitCode.HasValue)
                _connectionService._session.SendMessage(new ExitStatusMessage { RecipientChannel = ClientChannelId, ExitStatus = exitCode.Value });
            _connectionService._session.SendMessage(new ChannelCloseMessage { RecipientChannel = ClientChannelId });

            CheckBothClosed();
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
        {
            if (ServerClosed)
                return;

            ServerClosed = true;
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
        {
            if (Log.IsEnabled(LogLevel.Trace))
                Log.Trace($"Channel {ServerChannelId} received {data.Length} bytes.");
            ServerAttemptAdjustWindow((uint)data.Length);

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
                ClientWindowSize += bytesToAdd;

                // Wake every SendData loop parked on the window condition.
                // Monitor.PulseAll (not Pulse) so all blocked senders re-check;
                // the wake happens under the same lock, eliminating the old
                // Set/Thread.Sleep(1)/Reset pulse that stalled the SSH receive
                // thread once per WINDOW_ADJUST.
                Monitor.PulseAll(_windowLocker);

                // Also wake async senders parked in WaitForWindowAsync. Swap
                // in a fresh TCS and complete the old one so every awaiting
                // sender re-checks the window - but only when there IS an
                // awaiting sender. The common case (synchronous SendData, or
                // an async sender whose window never drained) then allocates
                // no TCS per WINDOW_ADJUST.
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

                // Wake any SendData loop parked on the window condition; it
                // re-checks _forceClosed and throws ObjectDisposedException,
                // matching the previous "waiting on a closed handle" semantics.
                Monitor.PulseAll(_windowLocker);

                // Also wake async senders parked in WaitForWindowAsync; they
                // re-check _forceClosed and throw ObjectDisposedException.
                if (_windowWaiters > 0)
                {
                    signal = _windowTcs;
                    _windowTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }

            signal?.TrySetResult(true);

            _connectionService.RemoveChannel(this);
        }
    }
}
