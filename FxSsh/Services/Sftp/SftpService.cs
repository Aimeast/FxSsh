using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Logging;
using FxSsh.Services;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// SFTP protocol engine (draft-ietf-secsh-filexfer-02, version 3),
    /// decoupled from any concrete storage via <see cref="ISftpFileSystem"/>.
    ///
    /// Inbound: feed channel data via <see cref="OnData"/> (frames may span
    /// SSH packets; accumulation and length validation happen here). Outbound:
    /// complete SFTP packets are raised through <see cref="DataReceived"/>,
    /// which <see cref="Attach"/> rewires directly to a channel's SendDataAsync.
    ///
    /// The engine performs no disk I/O: every operation delegates to the
    /// file system abstraction and translates its exceptions into SSH_FX_*
    /// status codes through a single mapping, so a failing backend can never
    /// crash the session.
    /// </summary>
    public sealed class SftpService : IDisposable
    {
        #region Protocol constants (draft-ietf-secsh-filexfer-02)

        // Requests (client -> server).
        private const byte SSH_FXP_INIT = 1;
        private const byte SSH_FXP_VERSION = 2;
        private const byte SSH_FXP_OPEN = 3;
        private const byte SSH_FXP_CLOSE = 4;
        private const byte SSH_FXP_READ = 5;
        private const byte SSH_FXP_WRITE = 6;
        private const byte SSH_FXP_LSTAT = 7;
        private const byte SSH_FXP_FSTAT = 8;
        private const byte SSH_FXP_SETSTAT = 9;
        private const byte SSH_FXP_FSETSTAT = 10;
        private const byte SSH_FXP_OPENDIR = 11;
        private const byte SSH_FXP_READDIR = 12;
        private const byte SSH_FXP_REMOVE = 13;
        private const byte SSH_FXP_MKDIR = 14;
        private const byte SSH_FXP_RMDIR = 15;
        private const byte SSH_FXP_REALPATH = 16;
        private const byte SSH_FXP_STAT = 17;
        private const byte SSH_FXP_RENAME = 18;
        private const byte SSH_FXP_READLINK = 19;
        private const byte SSH_FXP_SYMLINK = 20;
        private const byte SSH_FXP_EXTENDED = 200;

        // Responses (server -> client).
        private const byte SSH_FXP_STATUS = 101;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_DATA = 103;
        private const byte SSH_FXP_NAME = 104;
        private const byte SSH_FXP_ATTRS = 105;

        // Status codes.
        private const uint SSH_FX_OK = 0;
        private const uint SSH_FX_EOF = 1;
        private const uint SSH_FX_NO_SUCH_FILE = 2;
        private const uint SSH_FX_PERMISSION_DENIED = 3;
        private const uint SSH_FX_FAILURE = 4;
        private const uint SSH_FX_BAD_MESSAGE = 5;
        private const uint SSH_FX_OP_UNSUPPORTED = 8;

        /// <summary>Highest SFTP protocol version this engine implements.</summary>
        private const uint SupportedVersion = 3;

        /// <summary>
        /// Upper bound for a single SFTP frame. READ/WRITE payloads are capped
        /// separately (<see cref="MaxReadLength"/>); this guards the frame
        /// parser against a malicious length prefix that would otherwise
        /// allocate unbounded buffers.
        /// </summary>
        private const uint MaxPacketLength = 1 * 1024 * 1024;

        /// <summary>Per-request read cap, aligned with typical SSH channel packet sizes.</summary>
        private const int MaxReadLength = 64 * 1024;

        /// <summary>Entries returned per SSH_FXP_READDIR batch (draft allows one or more).</summary>
        private const int ReadDirBatchSize = 128;

        /// <summary>Maximum number of handles a single SFTP session may keep open.</summary>
        private const int MaximumOpenHandles = 256;

        #endregion

        /// <summary>
        /// Bounded inbound request queue used after <see cref="Attach"/>:
        /// each entry is one SSH channel data chunk (at most 32 KiB), so the
        /// cap bounds the engine's input memory to roughly 8 MiB instead of
        /// letting a pipelining client grow it without limit.
        /// </summary>
        private const int MaximumQueuedInboundChunks = 256;

        /// <summary>Bounded outbound response queue: caps in-flight replies at a few 64 KiB packets.</summary>
        private const int MaximumQueuedOutboundPackets = 8;

        private readonly ISftpFileSystem _fileSystem;
        private readonly Dictionary<string, HandleEntry> _mapOfHandle = [];
        private readonly CancellationTokenSource _cancellationTokenSource = new();
        private readonly object _lifecycleLocker = new();
        private readonly System.Threading.Channels.Channel<ChannelDataLease> _inboundQueue =
            System.Threading.Channels.Channel.CreateBounded<ChannelDataLease>(new System.Threading.Channels.BoundedChannelOptions(MaximumQueuedInboundChunks)
            {
                SingleReader = true,
                FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait,
            });
        private readonly System.Threading.Channels.Channel<OutboundPacket> _outboundQueue =
            System.Threading.Channels.Channel.CreateBounded<OutboundPacket>(new System.Threading.Channels.BoundedChannelOptions(MaximumQueuedOutboundPackets)
            {
                SingleReader = true,
                FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait,
            });

        /// <summary>Inbound frame accumulator: valid bytes live at [_pendingOffset, _pendingOffset + _pendingLength).</summary>
        private byte[] _pendingBytes = [];

        /// <summary>
        /// Read-response scratch buffer, reused across READ requests. The
        /// protocol engine processes requests on a single worker, and the
        /// bytes are copied into the response packet synchronously by
        /// <see cref="SendDataAsync"/>, so no request can observe another's data.
        /// </summary>
        private byte[] _readBuffer;
        private int _pendingOffset;
        private int _pendingLength;
        private int _handleCursor;
        private volatile bool _closed;
        private volatile bool _disposed;
        private volatile bool _peerEof;

        // Attach() moves request processing onto a single worker task so the
        // synchronous ISftpFileSystem calls never block the SSH message loop,
        // and responses are sent sequentially through a bounded queue.
        private SessionChannel _channel;
        private Task _workerTask;
        private Task _senderTask;
        private bool _asyncMode;

        /// <summary>
        /// Initializes a new instance of the <see cref="SftpService"/> class backed
        /// by a new <see cref="LocalFileSystem"/> rooted at <paramref name="rootPath"/>
        /// in read-write mode.
        /// </summary>
        /// <param name="rootPath">Directory that becomes the visible SFTP root ("/").</param>
        public SftpService(string rootPath)
            : this(new LocalFileSystem(rootPath), readOnly: false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SftpService"/> class backed
        /// by a new <see cref="LocalFileSystem"/> rooted at <paramref name="rootPath"/>.
        /// </summary>
        /// <param name="rootPath">Directory that becomes the visible SFTP root ("/").</param>
        /// <param name="readOnly">True to make the server reject every mutating SFTP request with SSH_FX_PERMISSION_DENIED.</param>
        public SftpService(string rootPath, bool readOnly)
            : this(new LocalFileSystem(rootPath), readOnly)
        {
        }

        /// <summary>
        /// Create an engine rooted at the current user's home directory -
        /// the conventional SFTP starting location.
        /// </summary>
        public SftpService()
            : this(LocalFileSystem.FromUserHome(), readOnly: false)
        {
        }

        /// <summary>
        /// Create an engine rooted at the current user's home directory in
        /// read-only mode.
        /// </summary>
        public SftpService(bool readOnly)
            : this(LocalFileSystem.FromUserHome(), readOnly)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SftpService"/> class backed
        /// by a custom <see cref="ISftpFileSystem"/> implementation, in read-write mode.
        /// </summary>
        /// <param name="fileSystem">Backend that performs the actual file system operations.</param>
        public SftpService(ISftpFileSystem fileSystem)
            : this(fileSystem, readOnly: false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SftpService"/> class backed
        /// by a custom <see cref="ISftpFileSystem"/> implementation.
        /// </summary>
        /// <param name="fileSystem">Backend that performs the actual file system operations.</param>
        /// <param name="readOnly">True to make the server reject every mutating SFTP request with SSH_FX_PERMISSION_DENIED.</param>
        public SftpService(ISftpFileSystem fileSystem, bool readOnly)
        {
            ArgumentNullException.ThrowIfNull(fileSystem);
            _fileSystem = fileSystem;
            IsReadOnly = readOnly;
        }

        /// <summary>
        /// True when the server rejects every mutating SFTP request (OPEN with
        /// write flags, WRITE, REMOVE, RENAME, MKDIR, RMDIR, SETSTAT,
        /// FSETSTAT) with SSH_FX_PERMISSION_DENIED. Read operations are
        /// unaffected.
        /// </summary>
        public bool IsReadOnly { get; }

        /// <summary>Complete outbound SFTP packets (length-prefixed frames).</summary>
        public event EventHandler<byte[]> DataReceived;

        /// <summary>Raised when the peer closes the channel; carries an exit code.</summary>
        public event EventHandler<uint> CloseReceived;

        /// <summary>
        /// Wire the engine to a session channel: inbound channel data feeds
        /// <see cref="OnData"/>, outbound packets go back through the channel,
        /// and peer close tears the engine down. One call replaces the manual
        /// event plumbing hosts previously wrote.
        /// </summary>
        /// <remarks>
        /// In this mode requests are processed on a dedicated worker task and
        /// responses are sent sequentially, so the synchronous file-system
        /// backend never blocks the SSH message loop and a client cannot grow
        /// an unbounded queue of pending replies.
        /// </remarks>
        public void Attach(SessionChannel channel)
        {
            ArgumentNullException.ThrowIfNull(channel);

            lock (_lifecycleLocker)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(SftpService));
                if (_asyncMode)
                    throw new InvalidOperationException("This SFTP engine is already attached to a channel.");

                _asyncMode = true;
                _channel = channel;
            }

            channel.LeaseReceived += (_, lease) => OnDataLease(lease);
            channel.EofReceived += (_, _) => OnPeerEof();
            channel.CloseReceived += (_, _) => OnClose();
            // Abrupt teardown (TCP drop, server stop) never delivers
            // CHANNEL_CLOSE; without this the open handles and WaitForClose
            // waiters would linger until GC.
            channel.ForceClosed += (_, _) => CloseCore(raiseEvent: false);

            // A peer-initiated close is answered with our own CHANNEL_CLOSE
            // carrying exit-status 0 (RFC 4254 6.10), so clients such as scp
            // observe a successful subsystem exit.
            CloseReceived += (_, exitCode) => _ = CloseChannelAsync(channel, exitCode);

            _senderTask = Task.Run(SenderLoopAsync);
            _workerTask = Task.Run(WorkerLoopAsync);
        }

        /// <summary>
        /// Feeds raw channel data into the engine. Bytes are buffered until
        /// one or more complete length-prefixed SFTP frames have arrived;
        /// each complete frame is dispatched to its request handler and any
        /// remainder is kept for the next call. A frame with an empty or
        /// oversized length prefix discards the buffered data.
        /// </summary>
        /// <param name="data">Inbound channel data; may contain partial or multiple SFTP frames.</param>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0)
                return;

            if (_asyncMode)
            {
                if (_closed)
                    return;

                // Manual callers hand over memory that may outlive this call,
                // so the copy is required; the attached path uses the pooled
                // lease event to avoid this copy.
                OnDataLease(ChannelDataLease.CopyFrom(data));
                return;
            }

            // Synchronous (manual event plumbing) mode: process inline. The
            // async core completes synchronously in this mode because no
            // outbound queue is involved.
            AppendPending(data.Span);
            ProcessPendingFramesAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Queue one pooled inbound chunk for the worker. The lease (or a
        /// pooled copy when the payload cannot be retained) is owned by the
        /// queue and disposed after the worker has appended it to the frame
        /// accumulator.
        /// </summary>
        private void OnDataLease(ChannelDataLease lease)
        {
            if (lease.Memory.Length == 0 || _closed)
            {
                lease.ReleaseIfNotRetained();
                return;
            }

            lease.TryRetainOrCopy(out var owned);
            if (!_inboundQueue.Writer.TryWrite(owned))
            {
                owned.Dispose();
                Log.Warn("SFTP: inbound request queue overflow; closing the channel.");
                Abort();
            }
        }

        /// <summary>
        /// Parse and dispatch every complete SFTP frame currently buffered.
        /// Runs on the worker in attached mode and on the caller in manual
        /// mode; the accumulator is never touched by two threads at once.
        /// </summary>
        private async ValueTask ProcessPendingFramesAsync()
        {
            while (_pendingLength >= 4)
            {
                if (_closed)
                    return;

                var length =
                    ((uint)_pendingBytes[_pendingOffset] << 24) |
                    ((uint)_pendingBytes[_pendingOffset + 1] << 16) |
                    ((uint)_pendingBytes[_pendingOffset + 2] << 8) |
                    _pendingBytes[_pendingOffset + 3];

                // Frame sanity: length field counts the bytes after itself, so
                // a full frame is length + 4. Reject empty and oversized frames
                // instead of letting a hostile length overflow the parser.
                if (length < 1 || length > MaxPacketLength)
                {
                    Log.Warn($"SFTP: discarding invalid frame length {length}.");
                    DiscardPending();
                    return;
                }

                var frameLength = (int)length + 4;
                if (_pendingLength < frameLength)
                    return; // wait for the rest of the frame

                // The frame payload starts AFTER the 4-byte length prefix;
                // packet type is payload[0], not the length prefix itself.
                // ProcessRequest runs synchronously, so the view stays valid.
                var payload = new ReadOnlyMemory<byte>(_pendingBytes, _pendingOffset + 4, (int)length);
                _pendingOffset += frameLength;
                _pendingLength -= frameLength;

                await ProcessRequestAsync(new SshDataReader(payload)).ConfigureAwait(false);
            }

            if (_pendingLength == 0)
                _pendingOffset = 0;
        }

        private async Task WorkerLoopAsync()
        {
            var token = _cancellationTokenSource.Token;
            try
            {
                await foreach (var lease in _inboundQueue.Reader.ReadAllAsync(token).ConfigureAwait(false))
                {
                    try
                    {
                        if (_closed)
                            break;

                        AppendPending(lease.Memory.Span);
                        await ProcessPendingFramesAsync().ConfigureAwait(false);
                    }
                    finally
                    {
                        lease.Dispose();
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Log.Fail("SFTP request worker failed.", ex);
            }
            finally
            {
                _outboundQueue.Writer.TryComplete();

                // Drop any queued leases the worker never consumed so their
                // pooled buffers return to the pool instead of leaking.
                while (_inboundQueue.Reader.TryRead(out var pending))
                    pending.Dispose();

                // Clean half-close: flush every response before sending EOF
                // and CHANNEL_CLOSE, so CLOSE can never overtake queued data.
                if (_peerEof && !_closed && !_disposed && _channel != null)
                {
                    // Bounded like every other teardown wait: a peer that
                    // stopped reading channel data must not park this flush
                    // forever (the session-level force close still releases
                    // everything when it fires).
                    try { await _senderTask.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false); } catch { }
                    try
                    {
                        await _channel.SendEofAsync().WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                    }
                    catch
                    {
                        // The channel stayed blocked; CloseCore below still
                        // releases the engine and its handles.
                    }
                    OnClose();
                }
            }
        }

        private async Task SenderLoopAsync()
        {
            try
            {
                await foreach (var packet in _outboundQueue.Reader.ReadAllAsync(_cancellationTokenSource.Token).ConfigureAwait(false))
                {
                    using (packet)
                    {
                        var channel = _channel;
                        if (channel == null)
                            continue;

                        await channel.SendDataAsync(packet.Memory).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Log.Fail("SFTP response sender failed.", ex);
                // A dead sender can never deliver another response: abort the
                // channel (EOF + CLOSE) and release the handles instead of
                // leaving a zombie session whose worker keeps consuming
                // requests while every response is discarded - the same
                // treatment the inbound-queue overflow gets.
                Abort();
            }
            finally
            {
                // Unblock a worker parked on a full response queue: with no
                // sender left, further WriteAsync calls must fail instead of
                // waiting forever. Drop queued rentals so their pooled
                // buffers return to the pool.
                _outboundQueue.Writer.TryComplete();
                while (_outboundQueue.Reader.TryRead(out var pending))
                    pending.Dispose();
            }
        }

        private void OnPeerEof()
        {
            if (_peerEof)
                return;

            _peerEof = true;
            // Let the worker drain the requests already received; it sends
            // EOF/CLOSE once every response has been flushed.
            _inboundQueue.Writer.TryComplete();
        }

        private void Abort()
        {
            if (_channel != null)
                _ = AbortChannelAsync(_channel);
            CloseCore(raiseEvent: false);
        }

        private static async Task CloseChannelAsync(SessionChannel channel, uint exitCode)
        {
            try
            {
                await channel.SendCloseAsync(exitCode).WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch { }
        }

        private static async Task AbortChannelAsync(SessionChannel channel)
        {
            try
            {
                await channel.SendEofAsync().WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch { }

            try
            {
                await channel.SendCloseAsync(1).WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch { }
        }

        /// <summary>
        /// Append raw channel bytes to the frame accumulator, compacting or
        /// growing as needed. Growth is amortized: capacity doubles instead
        /// of reallocating on every segment.
        /// </summary>
        private void AppendPending(ReadOnlySpan<byte> data)
        {
            var required = _pendingLength + data.Length;
            if (_pendingBytes.Length - _pendingOffset < required)
            {
                if (required <= _pendingBytes.Length)
                {
                    // Compact in place: move the unconsumed tail to the front.
                    Buffer.BlockCopy(_pendingBytes, _pendingOffset, _pendingBytes, 0, _pendingLength);
                }
                else
                {
                    var capacity = Math.Max(required, Math.Max(_pendingBytes.Length * 2, 4096));
                    var grown = new byte[capacity];
                    Buffer.BlockCopy(_pendingBytes, _pendingOffset, grown, 0, _pendingLength);
                    _pendingBytes = grown;
                }
                _pendingOffset = 0;
            }

            data.CopyTo(_pendingBytes.AsSpan(_pendingOffset + _pendingLength));
            _pendingLength += data.Length;
        }

        private void DiscardPending()
        {
            _pendingOffset = 0;
            _pendingLength = 0;
        }

        /// <summary>
        /// Tears the engine down in response to the peer closing the channel:
        /// cancels the token that <see cref="WaitForClose"/> blocks on,
        /// releases every open handle, and raises <see cref="CloseReceived"/>
        /// with an exit code of 0.
        /// </summary>
        public void OnClose() => CloseCore(raiseEvent: true);

        /// <summary>
        /// Shared teardown for peer close, forced close (abrupt disconnect,
        /// server shutdown) and abort. Both the peer's CHANNEL_CLOSE and
        /// session teardown can arrive; handles are released exactly once and
        /// the exit event fires at most once.
        /// </summary>
        private void CloseCore(bool raiseEvent)
        {
            lock (_lifecycleLocker)
            {
                if (_closed || _disposed)
                    return;
                _closed = true;

                _cancellationTokenSource.Cancel();
                _inboundQueue.Writer.TryComplete();
                _outboundQueue.Writer.TryComplete();
                CloseAllHandles();
            }

            if (raiseEvent)
                CloseReceived?.Invoke(this, 0);
        }

        /// <summary>Blocks the calling thread until the engine is closed via <see cref="OnClose"/>.</summary>
        public void WaitForClose()
        {
            try
            {
                Task.Delay(-1, _cancellationTokenSource.Token).Wait();
            }
            catch (AggregateException ex) when (ex.InnerException is TaskCanceledException)
            {
                // OnClose cancels the token: that is the normal wake-up.
            }
            catch (ObjectDisposedException)
            {
                // Dispose also releases waiters.
            }
        }

        /// <summary>Release every open handle (session teardown). Idempotent.</summary>
        public void Dispose()
        {
            lock (_lifecycleLocker)
            {
                if (_disposed)
                    return;
                _disposed = true;
                _closed = true;

                CloseAllHandles();
                // Cancel first so a thread parked in WaitForClose wakes up
                // and the worker/sender loops observe teardown. The CTS itself
                // is intentionally not disposed: the pump tasks may still be
                // unwinding from the cancellation.
                _cancellationTokenSource.Cancel();
                _inboundQueue.Writer.TryComplete();
                _outboundQueue.Writer.TryComplete();
            }
        }

        private void CloseAllHandles()
        {
            lock (_mapOfHandle)
            {
                foreach (var entry in _mapOfHandle.Values)
                {
                    // Teardown is best-effort: one failing flush must not
                    // prevent the remaining descriptors from being released
                    // (and must not escape into Channel.ForceClose, which
                    // invokes this from its event handlers).
                    try { entry.Dispose(); }
                    catch (Exception ex) { Log.Warn($"SFTP: closing a handle failed: {ex.Message}"); }
                }
                _mapOfHandle.Clear();
            }
        }

        #region Request dispatch

        private async ValueTask ProcessRequestAsync(SshDataReader reader)
        {
            var packetType = reader.ReadByte();
            var requestId = 0u;
            try
            {
                // Every request except INIT carries a uint32 request id right
                // after the type byte. Read it here so error responses below
                // can echo the correct id even when a handler throws after
                // consuming all its fields (reader state is then unusable).
                if (packetType != SSH_FXP_INIT)
                    requestId = reader.ReadUInt32();

                switch (packetType)
                {
                    case SSH_FXP_INIT: await ProcessInitAsync(reader).ConfigureAwait(false); break;
                    case SSH_FXP_OPEN: await ProcessOpenAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_CLOSE: await ProcessCloseAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_READ: await ProcessReadAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_WRITE: await ProcessWriteAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_LSTAT: await ProcessStatAsync(reader, requestId, followLinks: false).ConfigureAwait(false); break;
                    case SSH_FXP_STAT: await ProcessStatAsync(reader, requestId, followLinks: true).ConfigureAwait(false); break;
                    case SSH_FXP_FSTAT: await ProcessFStatAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_SETSTAT: await ProcessSetStatAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_FSETSTAT: await ProcessFSetStatAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_OPENDIR: await ProcessOpenDirAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_READDIR: await ProcessReadDirAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_REMOVE: await ProcessRemoveAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_MKDIR: await ProcessMakeDirAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_RMDIR: await ProcessRemoveDirAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_REALPATH: await ProcessRealPathAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_RENAME: await ProcessRenameAsync(reader, requestId).ConfigureAwait(false); break;
                    case SSH_FXP_READLINK:
                    case SSH_FXP_SYMLINK:
                    case SSH_FXP_EXTENDED:
                        // Not implemented: draft section 8 requires the server
                        // to answer unknown/unimplemented operations with
                        // SSH_FX_OP_UNSUPPORTED.
                        await SendStatusAsync(requestId, SSH_FX_OP_UNSUPPORTED, "Operation not supported.", "en").ConfigureAwait(false);
                        break;
                    default:
                        Log.Warn($"SFTP: unknown packet type 0x{packetType:X}.");
                        await SendStatusAsync(requestId, SSH_FX_OP_UNSUPPORTED, $"Unknown packet type 0x{packetType:X}.", "en").ConfigureAwait(false);
                        break;
                }
            }
            catch (Exception ex)
            {
                // Single mapping point: a backend failure becomes a status
                // response, never an exception escaping into the session.
                var (code, message) = MapException(ex);
                Log.Fail($"SFTP request failed (type 0x{packetType:X}, id {requestId}): {ex}");
                await SendStatusAsync(requestId, code, message, "en").ConfigureAwait(false);
            }
        }

        private async ValueTask ProcessInitAsync(SshDataReader reader)
        {
            // Draft section 4: the server replies with its own version. This
            // engine always speaks version 3 wire semantics, so answering a
            // v2 client with "2" while still emitting v3 ATTRS/OPEN frames
            // would desynchronise its parser; reply 3 like OpenSSH does.
            // Any extension data in INIT is ignored, as the draft mandates
            // for unrecognized extensions.
            reader.ReadUInt32();
            await SendInitAsync(SupportedVersion).ConfigureAwait(false);
        }

        /// <summary>
        /// Guard for mutating requests in read-only mode: replies
        /// SSH_FX_PERMISSION_DENIED and returns false when writes are
        /// disabled, so callers return without touching the file system.
        /// </summary>
        private async ValueTask<bool> EnsureWritableAsync(uint requestId)
        {
            if (!IsReadOnly)
                return true;

            await SendStatusAsync(requestId, SSH_FX_PERMISSION_DENIED, "Server is read-only.", "en").ConfigureAwait(false);
            return false;
        }

        private async ValueTask ProcessOpenAsync(SshDataReader reader, uint requestId)
        {
            var filename = reader.ReadString(Encoding.UTF8);
            var pflags = reader.ReadUInt32();
            var attributes = SftpFileAttributes.Read(reader);

            // Draft 6.3: TRUNC and EXCL are only valid combined with CREAT,
            // and the caller must request at least read or write access.
            var flags = (SftpOpenFlags)pflags;
            if ((flags & (SftpOpenFlags.Read | SftpOpenFlags.Write)) == 0 ||
                (flags & SftpOpenFlags.Truncate) != 0 && (flags & SftpOpenFlags.Create) == 0 ||
                (flags & SftpOpenFlags.Exclusive) != 0 && (flags & SftpOpenFlags.Create) == 0)
            {
                await SendStatusAsync(requestId, SSH_FX_BAD_MESSAGE, "Invalid open flags.", "en").ConfigureAwait(false);
                return;
            }

            // Read-only server: an open that requests any write capability
            // (WRITE/APPEND/CREAT/TRUNC/EXCL) is denied; pure reads pass.
            if ((flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create |
                          SftpOpenFlags.Truncate | SftpOpenFlags.Exclusive)) != 0)
            {
                if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                    return;
            }

            var handle = _fileSystem.OpenFile(filename, flags, attributes);
            var entry = HandleEntry.ForFile(handle);
            var registered = RegisterHandle(entry);
            if (registered == null)
            {
                entry.Dispose();
                if (!_closed && !_disposed)
                {
                    await SendStatusAsync(requestId, SSH_FX_FAILURE,
                        $"Too many open handles (limit {MaximumOpenHandles}).", "en").ConfigureAwait(false);
                }
                return;
            }

            await SendHandleAsync(requestId, registered).ConfigureAwait(false);
        }

        private async ValueTask ProcessCloseAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry))
                {
                    entry = null;
                }
                else
                {
                    _mapOfHandle.Remove(handle);
                }
            }

            if (entry == null)
            {
                await SendStatusAsync(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en").ConfigureAwait(false);
                return;
            }

            // Draft 6.3: close can fail (e.g. flushing cached writes); the
            // failure is reported but the handle is gone either way.
            try
            {
                entry.Dispose();
                await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                var (code, message) = MapException(ex);
                await SendStatusAsync(requestId, code, message, "en").ConfigureAwait(false);
            }
        }

        private async ValueTask ProcessReadAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var offset = reader.ReadUInt64();
            var length = reader.ReadUInt32();

            var entry = await FindFileHandleAsync(handle, requestId).ConfigureAwait(false);
            if (entry == null)
                return;

            if (offset > long.MaxValue)
            {
                await SendStatusAsync(requestId, SSH_FX_FAILURE, "Offset out of range.", "en").ConfigureAwait(false);
                return;
            }

            var buffer = _readBuffer ??= new byte[MaxReadLength];
            var count = (int)Math.Min(length, (uint)MaxReadLength);
            var readLength = entry.FileHandle.Read((long)offset, buffer.AsSpan(0, count));
            if (readLength > 0)
                await SendDataAsync(requestId, buffer.AsMemory(0, readLength)).ConfigureAwait(false);
            else
                await SendStatusAsync(requestId, SSH_FX_EOF, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessWriteAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var offset = reader.ReadUInt64();
            // Zero-copy view over the frame accumulator: the handle write is
            // synchronous and the bytes are not retained past this call.
            var data = reader.ReadBinaryAsMemory();

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            var entry = await FindFileHandleAsync(handle, requestId).ConfigureAwait(false);
            if (entry == null)
                return;

            if (offset > long.MaxValue)
            {
                await SendStatusAsync(requestId, SSH_FX_FAILURE, "Offset out of range.", "en").ConfigureAwait(false);
                return;
            }

            entry.FileHandle.Write((long)offset, data.Span);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessStatAsync(SshDataReader reader, uint requestId, bool followLinks)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var attributes = _fileSystem.GetAttributes(path, followLinks);
            await SendAttrsAsync(requestId, attributes).ConfigureAwait(false);
        }

        private async ValueTask ProcessFStatAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            // FSTAT never closes the handle (draft 6.8); only CLOSE does.
            var entry = await FindFileHandleAsync(handle, requestId).ConfigureAwait(false);
            if (entry == null)
                return;

            var attributes = entry.FileHandle.GetAttributes();
            await SendAttrsAsync(requestId, attributes).ConfigureAwait(false);
        }

        private async ValueTask ProcessSetStatAsync(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);
            var attributes = SftpFileAttributes.Read(reader);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            _fileSystem.SetAttributes(path, attributes);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessFSetStatAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var attributes = SftpFileAttributes.Read(reader);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            var entry = await FindFileHandleAsync(handle, requestId).ConfigureAwait(false);
            if (entry == null)
                return;

            entry.FileHandle.SetAttributes(attributes);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessOpenDirAsync(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var handle = _fileSystem.OpenDirectory(path);
            var entry = HandleEntry.ForDirectory(handle);
            var registered = RegisterHandle(entry);
            if (registered == null)
            {
                entry.Dispose();
                if (!_closed && !_disposed)
                {
                    await SendStatusAsync(requestId, SSH_FX_FAILURE,
                        $"Too many open handles (limit {MaximumOpenHandles}).", "en").ConfigureAwait(false);
                }
                return;
            }

            await SendHandleAsync(requestId, registered).ConfigureAwait(false);
        }

        private async ValueTask ProcessReadDirAsync(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry) || entry.Kind != HandleKind.Directory)
                    entry = null;
            }

            if (entry == null)
            {
                await SendStatusAsync(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en").ConfigureAwait(false);
                return;
            }

            // Page the directory: the handle stays valid until EOF or CLOSE
            // (draft 6.7), so a repeated READDIR keeps streaming entries.
            if (entry.EofReached)
            {
                await SendStatusAsync(requestId, SSH_FX_EOF, "", "").ConfigureAwait(false);
                return;
            }

            var files = entry.DirectoryHandle.ReadEntries(ReadDirBatchSize);
            if (files.Length == 0)
            {
                entry.EofReached = true;
                await SendStatusAsync(requestId, SSH_FX_EOF, "", "").ConfigureAwait(false);
                return;
            }

            await SendNameAsync(requestId, files).ConfigureAwait(false);
        }

        private async ValueTask ProcessRemoveAsync(SshDataReader reader, uint requestId)
        {
            var filename = reader.ReadString(Encoding.UTF8);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            _fileSystem.RemoveFile(filename);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessRenameAsync(SshDataReader reader, uint requestId)
        {
            var oldPath = reader.ReadString(Encoding.UTF8);
            var newPath = reader.ReadString(Encoding.UTF8);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            _fileSystem.Rename(oldPath, newPath);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessMakeDirAsync(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);
            var attributes = SftpFileAttributes.Read(reader);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            _fileSystem.MakeDirectory(path, attributes);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessRemoveDirAsync(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            if (!await EnsureWritableAsync(requestId).ConfigureAwait(false))
                return;

            _fileSystem.RemoveDirectory(path);
            await SendStatusAsync(requestId, SSH_FX_OK, "", "").ConfigureAwait(false);
        }

        private async ValueTask ProcessRealPathAsync(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var realPath = _fileSystem.RealPath(path);
            var dummy = new SftpFileEntry { FileName = realPath, Attributes = new SftpFileAttributes() };
            await SendNameAsync(requestId, [dummy]).ConfigureAwait(false);
        }

        #endregion

        #region Handle registry

        /// <summary>
        /// Register an open handle, or return null when the per-session cap
        /// is reached or the engine is already closed. The caller owns (and
        /// must dispose) <paramref name="entry"/> when registration fails.
        /// The closed check runs under the map lock: a close that cleared the
        /// map between <see cref="ISftpFileSystem.OpenFile"/> and this call
        /// would otherwise leave the entry registered in a map that will
        /// never be drained again, leaking the descriptor until GC.
        /// </summary>
        private string RegisterHandle(HandleEntry entry)
        {
            lock (_mapOfHandle)
            {
                if (_closed || _disposed)
                    return null;
                if (_mapOfHandle.Count >= MaximumOpenHandles)
                    return null;

                var handle = (++_handleCursor).ToString(CultureInfo.InvariantCulture);
                _mapOfHandle.Add(handle, entry);
                return handle;
            }
        }

        /// <summary>Resolve a file handle, replying FAILURE when missing or a directory handle.</summary>
        private async ValueTask<HandleEntry> FindFileHandleAsync(string handle, uint requestId)
        {
            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry) || entry.Kind != HandleKind.File)
                    entry = null;
            }

            if (entry == null)
                await SendStatusAsync(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en").ConfigureAwait(false);
            return entry;
        }

        private enum HandleKind { File, Directory }

        private sealed class HandleEntry : IDisposable
        {
            public HandleKind Kind { get; private set; }
            public ISftpFileHandle FileHandle { get; private set; }
            public ISftpDirectoryHandle DirectoryHandle { get; private set; }

            /// <summary>True once a READDIR batch returned empty (draft 6.7 EOF).</summary>
            public bool EofReached { get; set; }

            public static HandleEntry ForFile(ISftpFileHandle handle)
                => new() { Kind = HandleKind.File, FileHandle = handle };

            public static HandleEntry ForDirectory(ISftpDirectoryHandle handle)
                => new() { Kind = HandleKind.Directory, DirectoryHandle = handle };

            public void Dispose()
            {
                FileHandle?.Dispose();
                DirectoryHandle?.Dispose();
            }
        }

        #endregion

        #region Response building

        /// <summary>
        /// One complete response packet whose buffer was detached from an
        /// <see cref="SshDataWriter"/>. The sender loop owns it until the
        /// channel has framed the data and returns the rental here.
        /// </summary>
        private sealed class OutboundPacket : IDisposable
        {
            private byte[] _buffer;
            private readonly int _length;

            public OutboundPacket(byte[] buffer, int length)
            {
                _buffer = buffer;
                _length = length;
            }

            public ReadOnlyMemory<byte> Memory => _buffer == null
                ? throw new ObjectDisposedException(nameof(OutboundPacket))
                : _buffer.AsMemory(0, _length);

            public void Dispose()
            {
                var buffer = Interlocked.Exchange(ref _buffer, null);
                if (buffer != null)
                    SshBuffers.Packets.Return(buffer);
            }
        }

        /// <summary>
        /// Complete an outbound SFTP packet: write its length prefix and hand
        /// it either to the public event (manual mode) or to the attached
        /// sender queue. In attached mode the writer's pooled buffer is
        /// detached and transferred to the queue, so a 64 KiB READ response
        /// does not go through an extra exact-array allocation/copy.
        /// </summary>
        private async ValueTask SendPacketAsync(SshDataWriter writer)
        {
            var packetLength = writer.Length;
            var frameLength = packetLength - 4;
            Debug.Assert(frameLength >= 4, "SFTP responses must contain at least a type and request id.");

            if (!_asyncMode)
            {
                var packet = writer.ToByteArray();
                WriteLengthPrefix(packet, frameLength);
                DataReceived?.Invoke(this, packet);
                return;
            }

            var buffer = writer.DetachBuffer();
            WriteLengthPrefix(buffer, frameLength);
            var outbound = new OutboundPacket(buffer, packetLength);
            var enqueued = false;
            try
            {
                // Attached mode: hand the response to the single sender loop
                // and await capacity instead of blocking the worker thread.
                // In-flight response memory stays bounded even if the peer
                // stops reading its window.
                await _outboundQueue.Writer.WriteAsync(outbound, _cancellationTokenSource.Token)
                    .ConfigureAwait(false);
                enqueued = true;
            }
            // ChannelClosedException and ObjectDisposedException both derive
            // from InvalidOperationException; teardown simply drops the reply.
            catch (InvalidOperationException) { }
            catch (OperationCanceledException) { }
            finally
            {
                if (!enqueued)
                    outbound.Dispose();
            }
        }

        private static void WriteLengthPrefix(byte[] packet, int frameLength)
        {
            packet[0] = (byte)(frameLength >> 24);
            packet[1] = (byte)(frameLength >> 16);
            packet[2] = (byte)(frameLength >> 8);
            packet[3] = (byte)frameLength;
        }

        private async ValueTask SendStatusAsync(uint requestId, uint statusCode, string message, string language)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_STATUS);
            writer.Write(requestId);
            writer.Write(statusCode);
            writer.Write(message, Encoding.UTF8);   // draft section 7: message is UTF-8
            writer.Write(language, Encoding.ASCII);
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        private async ValueTask SendInitAsync(uint version)
        {
            using var writer = new SshDataWriter(9);
            writer.Write(0u);
            writer.Write(SSH_FXP_VERSION);
            writer.Write(version);
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        private async ValueTask SendHandleAsync(uint requestId, string handle)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_HANDLE);
            writer.Write(requestId);
            writer.Write(handle, Encoding.ASCII);
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        private async ValueTask SendDataAsync(uint requestId, ReadOnlyMemory<byte> bytes)
        {
            // Exact capacity: 4 (length prefix) + 1 (type) + 4 (id)
            // + 4 (string length) + payload. This avoids the doubling
            // reallocations and keeps a 64 KiB response inside the 128 KiB
            // pool bucket instead of allocating a 128 KiB LOH array.
            using var writer = new SshDataWriter(13 + bytes.Length);
            writer.Write(0u);
            writer.Write(SSH_FXP_DATA);
            writer.Write(requestId);
            writer.WriteBinary(bytes);
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        private async ValueTask SendNameAsync(uint requestId, SftpFileEntry[] entries)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_NAME);
            writer.Write(requestId);
            writer.Write((uint)entries.Length);
            foreach (var entry in entries)
            {
                writer.Write(entry.FileName, Encoding.UTF8);
                writer.Write(FormatLongName(entry), Encoding.UTF8);
                // A backend that cannot determine attributes may return null
                // (documented on SftpFileEntry.Attributes); an empty attribute
                // block (flags = 0) is the protocol-legal "no attributes"
                // answer, so a whole NAME batch never fails on one entry.
                (entry.Attributes ?? new SftpFileAttributes()).Write(writer);
            }
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        private async ValueTask SendAttrsAsync(uint requestId, SftpFileAttributes attributes)
        {
            if (attributes == null)
            {
                // A backend that returns no attributes is a backend failure,
                // not an empty attribute block: report it as a status error so
                // the client never mistakes missing metadata for a real file.
                await SendStatusAsync(requestId, SSH_FX_FAILURE,
                    "The file system backend returned no attributes.", "en").ConfigureAwait(false);
                return;
            }

            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_ATTRS);
            writer.Write(requestId);
            attributes.Write(writer);
            await SendPacketAsync(writer).ConfigureAwait(false);
        }

        /// <summary>
        /// ls -l style display string (draft section 7 recommends, but does
        /// not require, this format; clients must not parse it).
        /// </summary>
        private static string FormatLongName(SftpFileEntry entry)
        {
            var attrs = entry.Attributes;
            var perms = attrs?.Permissions ?? 0x81B6u;
            var type = (perms & 0xF000) switch
            {
                0x4000 => 'd',   // directory
                0xA000 => 'l',   // symbolic link
                _ => '-',
            };
            var size = attrs?.Size?.ToString() ?? "0";
            var mtime = attrs?.ModificationTime != null
                ? DateTimeOffset.FromUnixTimeSeconds(attrs.ModificationTime.Value).ToString("MMM d HH:mm", CultureInfo.InvariantCulture)
                : "Jan 1 00:00";
            return $"{type}{ModeString(perms)} 1 owner group {size,10} {mtime} {entry.FileName}";
        }

        private static string ModeString(uint perms)
        {
            Span<char> mode = stackalloc char[9];
            for (var i = 0; i < 3; i++)
            {
                var shift = 6 - i * 3;
                mode[i * 3 + 0] = (perms & (1u << (shift + 2))) != 0 ? 'r' : '-';
                mode[i * 3 + 1] = (perms & (1u << (shift + 1))) != 0 ? 'w' : '-';
                mode[i * 3 + 2] = (perms & (1u << shift)) != 0 ? 'x' : '-';
            }
            return new string(mode);
        }

        #endregion

        #region Error mapping

        /// <summary>
        /// Single mapping from backend exceptions to SSH_FX_* codes (draft
        /// section 7 status semantics): missing files map to NO_SUCH_FILE,
        /// access failures to PERMISSION_DENIED, everything else to FAILURE.
        /// </summary>
        private static (uint Code, string Message) MapException(Exception ex)
        {
            return ex switch
            {
                FileNotFoundException or DirectoryNotFoundException => (SSH_FX_NO_SUCH_FILE, ex.Message),
                UnauthorizedAccessException => (SSH_FX_PERMISSION_DENIED, ex.Message),
                ArgumentException => (SSH_FX_BAD_MESSAGE, ex.Message),
                IOException => (SSH_FX_FAILURE, ex.Message),
                _ => (SSH_FX_FAILURE, ex.Message),
            };
        }

        #endregion
    }
}
