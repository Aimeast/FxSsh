using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh.Algorithms;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Services;

namespace FxSsh
{
    public class Session
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize;
        // Advertised receive window (RFC 4254 section 5.3). 2 MiB matches the
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

        // Active algorithm set for this session; copied from the server's
        // pluggable AlgorithmSelection registry in the ctor (see below).
        private readonly Dictionary<string, Func<KexAlgorithm>> _keyExchangeAlgorithms;
        internal readonly Dictionary<string, Func<string, PublicKeyAlgorithm>> _publicKeyAlgorithms;
        private readonly Dictionary<string, Func<CipherInfo>> _encryptionAlgorithms;
        private readonly Dictionary<string, Func<HmacInfo>> _hmacAlgorithms;
        private readonly Dictionary<string, Func<CompressionAlgorithm>> _compressionAlgorithms;

        // Per-category tags used to warn when a Custom/Obsolete entry is actually
        // negotiated. Names map 1:1 with the algorithm dictionaries above.
        private readonly Dictionary<string, HazmatAlgorithmTag> _keyExchangeTags;
        private readonly Dictionary<string, HazmatAlgorithmTag> _publicKeyTags;
        private readonly Dictionary<string, HazmatAlgorithmTag> _encryptionTags;
        private readonly Dictionary<string, HazmatAlgorithmTag> _hmacTags;
        private readonly Dictionary<string, HazmatAlgorithmTag> _compressionTags;

        private readonly object _locker = new();
        private Socket _socket;
        private bool _disconnected;
        private readonly Dictionary<string, string> _hostKey;

        // Async transport core. Raw socket bytes flow in through _receivePipe
        // (filled by FillPipeAsync) and are consumed as framed packets by
        // ProcessPipeAsync; outbound wire buffers are enqueued to _sendChannel
        // by SendMessageInternal and written by the single-reader send pump
        // (ProcessSendChannelAsync). No thread is ever blocked on socket I/O,
        // so thousands of sessions do not consume a thread each - the
        // ConnectionService.MessageLoop and the per-session pumps are all
        // async tasks that park on the pipe/channel instead.
        private readonly Pipe _receivePipe = new();
        private readonly System.Threading.Channels.Channel<PooledBuffer> _sendChannel =
            System.Threading.Channels.Channel.CreateUnbounded<PooledBuffer>(new UnboundedChannelOptions { SingleReader = true });

        private CancellationTokenSource _sessionCts;

        // Server-side keepalive. IdleThreshold is both the idle threshold that
        // starts the probing and the resend cadence once probing has started.
        // Probes are counted; MaxMissedProbes unanswered probes disconnect the
        // session. Both directions of traffic refresh _lastActivity (sending a
        // frame also proves the link is alive and advances the peer's ACK).
        private const int MaxMissedProbes = 3;
        private TimeSpan _keepaliveIdle = TimeSpan.Zero;   // <=0 means disabled
        private Stopwatch _lastActivity;
        private int _missedProbes;
        private Timer _keepaliveTimer;

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private Algorithms _algorithms = null;
        private ExchangeContext _exchangeContext = null;
        private List<SshService> _services = [];

        // Protocol extensions (RFC 8308)
        private Dictionary<string, string> _extensionsToSend = [];
        private bool _clientAdvertisedExtInfo;  // client KEXINIT had "ext-info-c"
        private ConcurrentQueue<Message> _blockedMessages = new();
        private bool _discardNextKexPacket;

        private static long _nextId = 0;
        public long Id { get; }
        public ConcurrentDictionary<Type, object> ContextData { get; } = new();

        public string ServerVersion { get; private set; }
        public string ClientVersion { get; private set; }
        public byte[] SessionId { get; private set; }
        public T GetService<T>() where T : SshService
        {
            return (T)_services.FirstOrDefault(x => x is T);
        }

        public Session(Socket socket, Dictionary<string, string> hostKey, string serverBanner, AlgorithmSelection algorithms = null)
        {
            ArgumentNullException.ThrowIfNull(socket);
            ArgumentNullException.ThrowIfNull(hostKey);

            Id = Interlocked.Increment(ref _nextId);
            _socket = socket;
            _hostKey = hostKey.ToDictionary(s => s.Key, s => s.Value);
            ServerVersion = serverBanner;

            // The server's pluggable registry (seeded from AlgorithmRegistry
            // and mutable via SshServer.Algorithms.ConfigureHazmat) is the source
            // of truth for every category, filtered by any selectors set on it.
            // The per-session dictionaries are copies taken at construction so
            // later mutations to the shared registry do not disturb an in-flight
            // session.
            algorithms ??= new AlgorithmSelection();
            _keyExchangeAlgorithms = CopyFactories(algorithms.KeyExchange);
            _publicKeyAlgorithms = CopyFactories(algorithms.PublicKey);
            _encryptionAlgorithms = CopyFactories(algorithms.Encryption);
            _hmacAlgorithms = CopyFactories(algorithms.Hmac);
            _compressionAlgorithms = CopyFactories(algorithms.Compression);
            _keyExchangeTags = CopyTags(algorithms.KeyExchange);
            _publicKeyTags = CopyTags(algorithms.PublicKey);
            _encryptionTags = CopyTags(algorithms.Encryption);
            _hmacTags = CopyTags(algorithms.Hmac);
            _compressionTags = CopyTags(algorithms.Compression);

            // RFC 8332: advertise which signature algorithms we accept for
            // publickey auth. OpenSSH 8.8+ refuses to sign unless the server
            // sends server-sig-algs (it assumes legacy ssh-rsa otherwise),
            // and we advertise "ext-info-s" in KEXINIT, so this must be sent.
            RegisterExtension("server-sig-algs", string.Join(",", _publicKeyAlgorithms.Keys));
        }

        private static Dictionary<string, TFactory> CopyFactories<TFactory>(
            IReadOnlyList<(string Name, TFactory Factory, HazmatAlgorithmTag Tag)> entries)
            => entries.ToDictionary(e => e.Name, e => e.Factory);

        private static Dictionary<string, HazmatAlgorithmTag> CopyTags<TFactory>(
            IReadOnlyList<(string Name, TFactory Factory, HazmatAlgorithmTag Tag)> entries)
            => entries.ToDictionary(e => e.Name, e => e.Tag);

        public event EventHandler<EventArgs> Disconnected;

        public event EventHandler<SshService> ServiceRegistered;

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
                return;
            }

            _sessionCts = new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionCts.Token, externalToken);

            SetSocketOptions();

            var fillPipeTask = FillPipeAsync(linkedCts.Token);
            var processPipeTask = ProcessPipeAsync(linkedCts.Token);
            var sendTask = ProcessSendChannelAsync(linkedCts.Token);

            try
            {
                await Task.WhenAll(fillPipeTask, processPipeTask, sendTask);
            }
            catch (Exception ex)
            {
                await DisconnectAsync(DisconnectReason.ProtocolError, ex.Message);
            }
        }

        public async Task DisconnectAsync(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            bool runTeardown;
            lock (_locker)
            {
                runTeardown = !_disconnected;
                _disconnected = true;
            }
            if (!runTeardown)
            {
                return;
            }

            _keepaliveTimer?.Dispose();
            _keepaliveTimer = null;

            if (reason == DisconnectReason.ByApplication)
            {
                var message = new DisconnectMessage(reason, description);
                TrySendMessage(message);
            }

            _sendChannel.Writer.TryComplete();

            if (_sessionCts is { IsCancellationRequested: false })
                await _sessionCts.CancelAsync();

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

            Log.Info($"Session disconnected: {reason} - {description}");
            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            _ = DisconnectAsync(reason, description);
        }

        #region Socket operations
        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.NoDelay = true;
            _socket.LingerState = new LingerOption(enable: false, seconds: 0);
            _socket.ReceiveBufferSize = socketBufferSize;
            _socket.SendBufferSize = socketBufferSize;
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
                    var bytesRead = await _socket.ReceiveAsync(memory, SocketFlags.None, token);
                    if (bytesRead == 0) break;

                    _receivePipe.Writer.Advance(bytesRead);
                    var result = await _receivePipe.Writer.FlushAsync(token);
                    if (result.IsCompleted) break;
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                await _receivePipe.Writer.CompleteAsync(ex);
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
                var banner = Encoding.ASCII.GetBytes(ServerVersion + "\r\n");
                var bannerBuf = SshBuffers.Packets.Rent(banner.Length);
                banner.CopyTo(bannerBuf.AsSpan());
                _sendChannel.Writer.TryWrite(new PooledBuffer(bannerBuf, banner.Length));

                ClientVersion = await ReadProtocolVersionAsync(token);
                Log.Info($"Client version: {ClientVersion}.");
                if (!Regex.IsMatch(ClientVersion, "SSH-2.0-.+"))
                {
                    Log.Warn($"Unsupported client SSH version: {ClientVersion}.");
                    throw new SshConnectionException(
                        string.Format("Not supported for client SSH version {0}. This server only supports SSH v2.0.", ClientVersion),
                        DisconnectReason.ProtocolVersionNotSupported);
                }

                Log.Debug("Session established, starting key exchange.");
                ConsiderReExchange(true);

                while (!token.IsCancellationRequested)
                {
                    var message = await ReceiveMessageAsync(token);
                    if (message is null) break;

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
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                await DisconnectAsync(DisconnectReason.ProtocolError, ex.Message);
            }
            finally
            {
                foreach (var service in _services)
                {
                    service.CloseService();
                }
                await _receivePipe.Reader.CompleteAsync();
                _ = DisconnectAsync();
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
                        var memory = new ReadOnlyMemory<byte>(payload.Array, 0, payload.Length);
                        await _socket.SendAsync(memory, SocketFlags.None, token);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                throw new SshConnectionException("Socket send operation failed.", DisconnectReason.ConnectionLost, ex);
            }
        }

        /// <summary>
        /// A pooled byte buffer rented from <see cref="ArrayPool{byte}.Shared"/>
        /// that flows between the async pumps. Unlike the old ref struct
        /// (which could only live on the stack), this one is stored inside
        /// <see cref="_sendChannel"/> and <see cref="Pipe"/>-backed reads, so
        /// it must be a plain struct. Dispose returns the rental to the pool.
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
            if (length < 0 || length > MaximumPacketLength + 4 + 64)
            {
                throw new SshConnectionException(
                    string.Format("Invalid read length {0}.", length),
                    DisconnectReason.ProtocolError);
            }

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

                    var version = Encoding.ASCII.GetString(lineSequence);
                    _receivePipe.Reader.AdvanceTo(buffer.GetPosition(1, endOfLine.Value));
                    return version;
                }

                if (result.IsCompleted)
                    throw new SshConnectionException("Connection closed before protocol version exchange.", DisconnectReason.ConnectionLost);

                _receivePipe.Reader.AdvanceTo(buffer.Start, buffer.End);
            }
            throw new OperationCanceledException();
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
                    var dataLength = packetLength - paddingLength - 1;
                    var data = plaintext.AsMemory(1, dataLength);
                    // none-compression is the identity: hand the decrypted
                    // slice straight to LoadMessage instead of ToArray()'ing
                    // a copy. Safe because the pooled plaintext is consumed
                    // synchronously downstream (message loop thread) before
                    // the next packet's Rent reuses it.
                    if (_algorithms.ClientCompression.IsIdentity)
                        return LoadMessage(data.Span[0], data, packetLength);

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
                    SshBuffers.Packets.Return(plaintext);
                }
            }

            // OpenSSH Encrypt-then-MAC (RFC 6668): packet_length is NOT encrypted.
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
                using var cipher = await ReadFromPipeAsync(packetLength, token);
                if (cipher.Length == 0) return null;

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
                var dataLength = packetLength - paddingLength - 1;
                var data = cipher.Memory.Slice(1, dataLength);
                // none-compression is the identity: hand the decrypted slice
                // straight to LoadMessage instead of ToArray()'ing a copy.
                // Safe for the same reason as the AEAD path above.
                if (_algorithms.ClientCompression.IsIdentity)
                    return LoadMessage(data.Span[0], data, packetLength);

                var dataArray = _algorithms.ClientCompression.Decompress(data).ToArray();

                return LoadMessage(dataArray[0], dataArray, packetLength);
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
            var bytesToRead = packetLengthNonEtm - blockSize + 4;

            using var followingBlocks = await ReadFromPipeAsync(bytesToRead, token);
            if (followingBlocks.Length == 0 && bytesToRead > 0) return null;
            if (useAlg && followingBlocks.Length > 0)
                _algorithms.ClientEncryption.Transform(followingBlocks.Array, bytesToRead, followingBlocks.Array);

            // RFC 4253 section 6: payload length = packet_length - padding_length - 1
            // (the -1 is the padding_length byte itself). The AEAD/ETM paths
            // above compute the same with - 1; omitting it here would leave a
            // trailing padding byte in every message, breaking byte-exact
            // consumers (public-key signature verification data).
            var dataLengthNonEtm = packetLengthNonEtm - paddingLengthNonEtm - 1;
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

            lock (_locker)
            {
                _inboundPacketSequence++;
                _inboundFlow += (uint)packetLength;
            }

            ConsiderReExchange();

            // Any inbound frame proves the link is alive; refresh the keepalive
            // idle clock so probing does not fire while the peer is active.
            _lastActivity?.Restart();

            return message;
        }

        internal void SendMessage(Message message)
        {
            ArgumentNullException.ThrowIfNull(message);

            if (_exchangeContext != null
                && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
            {
                // Rekey window: the message is queued by reference and only
                // framed later (ContinueSendBlockedMessages after NEWKEYS).
                // ChannelDataMessage.Data is a zero-copy slice over a
                // caller/receive buffer that may be recycled before the
                // flush, so snapshot the payload now to keep the queued
                // chunk intact. Other messages carry scalar fields only and
                // are safe to queue as-is.
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

            lock (_locker)
                SendMessageInternal(message);
        }

        private void SendMessageInternal(Message message)
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
                payloadWriter = new SshDataWriter();
                message.WritePayload(payloadWriter);
                payloadLength = payloadWriter.Length;
            }

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            //
            // OpenSSH ETM (RFC 6668) and AEAD (RFC 5647) both transmit
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

            // Frame the packet into a rented plaintext buffer:
            // [packet_length(4)][padding_length(1)][payload][padding]. The old
            // shared _sendScratchBuffer is gone: the send pump consumes each
            // wire buffer asynchronously, so every packet must own its buffers
            // until the pump has written them (ArrayPool rentals returned by
            // PooledBuffer.Dispose). No per-packet heap allocation.
            var framedLength = 4 + (int)packetLength;
            var scratch = SshBuffers.Packets.Rent(framedLength);
            try
            {
                var frame = scratch.AsSpan(0, framedLength);
                frame[0] = (byte)(packetLength >> 24);
                frame[1] = (byte)(packetLength >> 16);
                frame[2] = (byte)(packetLength >> 8);
                frame[3] = (byte)packetLength;
                frame[4] = paddingLength;
                if (payload != null)
                    payload.AsSpan().CopyTo(frame.Slice(5));
                else
                    // Copy the pooled writer's bytes into the frame; TryWriteTo
                    // also returns the writer's rental to the pool, so subsequent
                    // Dispose is a no-op.
                    payloadWriter.TryWriteTo(frame.Slice(5));
                RandomNumberGenerator.Fill(frame.Slice(5 + payloadLength, paddingLength));

                payloadWriter?.Dispose();

                int finalLength = framedLength;
                if (useAlg)
                {
                    if (isAead)
                        finalLength += _algorithms.ServerEncryption.TagBytes;
                    else
                        finalLength += _algorithms.ServerHmac.DigestLength;
                }

                var sendBuf = SshBuffers.Packets.Rent(finalLength);
                var wire = sendBuf.AsSpan(0, finalLength);

                if (useAlg)
                {
                    if (isAead)
                    {
                        // RFC 5647 section 3 + 7.3 AEAD layout:
                        // [length_field(4)][ciphertext = encrypt(padding_length||payload||padding)][tag(16)].
                        // The AEAD transform owns the length field and the inline
                        // tag: GCM transmits packet_length as plaintext AAD
                        // (authenticated but not encrypted), chacha20-poly1305@openssh.com
                        // encrypts it. Encrypt straight into the rented sendBuf -
                        // no intermediate ciphertext array.
                        _algorithms.ServerEncryption.EncryptAead(_outboundPacketSequence, frame, wire);
                    }
                    else if (_algorithms.ServerHmacIsEtm)
                    {
                        // OpenSSH Encrypt-then-MAC (RFC 6668): packet_length is NOT
                        // encrypted. Layout: [length(4, plaintext)][encrypt(padding_length||payload||padding)][MAC].
                        // MAC covers seq || length || ciphertext.
                        // Encrypt the body in place inside the scratch buffer
                        // (frame[4..] becomes ciphertext), compute the MAC into
                        // stackalloc, then assemble the wire packet in sendBuf.
                        var cipherLen = framedLength - 4;
                        _algorithms.ServerEncryption.Transform(scratch, 4, cipherLen, scratch, 4);

                        Span<byte> mac = stackalloc byte[_algorithms.ServerHmac.DigestLength];
                        ComputeHmac(_algorithms.ServerHmac, frame.Slice(0, 4), frame.Slice(4, cipherLen), _outboundPacketSequence, mac);

                        frame.Slice(0, 4 + cipherLen).CopyTo(wire);
                        mac.CopyTo(wire.Slice(4 + cipherLen));
                    }
                    else
                    {
                        // RFC 4253: the whole packet is encrypted; MAC covers the plaintext.
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

                if (!_sendChannel.Writer.TryWrite(new PooledBuffer(sendBuf, finalLength)))
                {
                    SshBuffers.Packets.Return(sendBuf);
                    throw new SshConnectionException("Could not enqueue message for sending.", DisconnectReason.ByApplication);
                }
            }
            finally
            {
                SshBuffers.Packets.Return(scratch);
            }

            if (Log.IsEnabled(LogLevel.Trace))
            {
                Log.Trace($"Sent msg={message.GetType().Name} seq={_outboundPacketSequence}");
            }

            lock (_locker)
            {
                _outboundPacketSequence++;
                _outboundFlow += packetLength;
            }

            ConsiderReExchange();

            // Outbound traffic also proves the link is alive (and advances the
            // peer's ACK), so it counts toward keepalive idle resetting.
            _lastActivity?.Restart();
        }

        private void ConsiderReExchange(bool force = false)
        {
            var kex = false;
            lock (_locker)
                if (_exchangeContext == null
                    && (force || _inboundFlow + _outboundFlow > 1024 * 1024 * 512)) // 0.5 GiB
                {
                    _exchangeContext = new ExchangeContext();
                    kex = true;
                }

            if (kex)
            {
                Log.Debug(force ? "Key exchange triggered (forced)."
                    : "Key exchange triggered (traffic threshold reached).");
                var kexInitMessage = LoadKexInitMessage();
                _exchangeContext.ServerKexInitPayload = kexInitMessage.GetPacket();

                SendMessage(kexInitMessage);
            }
        }

        private void ContinueSendBlockedMessages()
        {
            if (_blockedMessages.Count > 0)
            {
                Message message;
                while (_blockedMessages.TryDequeue(out message))
                {
                    SendMessageInternal(message);
                }
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

            var message = new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = kexAlgs.ToArray(),
                ServerHostKeyAlgorithms = _publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray(),
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

            if (Log.IsEnabled(LogLevel.Info))
                Log.Info("Client cipher suites: " +
                    $"kex=[{string.Join(",", message.KeyExchangeAlgorithms)}], hostkey=[{string.Join(",", message.ServerHostKeyAlgorithms)}], " +
                    $"cipher ctos=[{string.Join(",", message.EncryptionAlgorithmsClientToServer)}], stoc=[{string.Join(",", message.EncryptionAlgorithmsServerToClient)}], " +
                    $"mac ctos=[{string.Join(",", message.MacAlgorithmsClientToServer)}], stoc=[{string.Join(",", message.MacAlgorithmsServerToClient)}], " +
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

            // The bitwise & (not short-circuiting &&) guarantees every out
            // parameter is assigned even when an earlier check is false.
            var isGuessed =
                ChooseAlgorithm([.. _keyExchangeAlgorithms.Keys], message.KeyExchangeAlgorithms, out _exchangeContext.KeyExchange) &
                ChooseAlgorithm(_publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray(), message.ServerHostKeyAlgorithms, out _exchangeContext.PublicKey) &
                ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsClientToServer, out _exchangeContext.ClientEncryption) &
                ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsServerToClient, out _exchangeContext.ServerEncryption) &
                ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsClientToServer, out _exchangeContext.ClientHmac) &
                ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsServerToClient, out _exchangeContext.ServerHmac) &
                ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsClientToServer, out _exchangeContext.ClientCompression) &
                ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsServerToClient, out _exchangeContext.ServerCompression);

            // RFC 4253 7.1: if the client optimistically sent a first KEX
            // packet and its algorithm guess was wrong, discard that packet.
            if (message.FirstKexPacketFollows && !isGuessed)
                _discardNextKexPacket = true;

            _exchangeContext.ClientKexInitPayload = message.GetPacket();

            Log.Info($"Negotiated: kex={_exchangeContext.KeyExchange}, hostkey={_exchangeContext.PublicKey}, " +
                $"ctos={_exchangeContext.ClientEncryption}:{_exchangeContext.ClientHmac}:{_exchangeContext.ClientCompression}, " +
                $"stoc={_exchangeContext.ServerEncryption}:{_exchangeContext.ServerHmac}:{_exchangeContext.ServerCompression}.");

            WarnIfHazmatNegotiated();

            // RFC 8308: remember whether the client supports EXT_INFO.
            _clientAdvertisedExtInfo = message.PeerExtensions.Contains("ext-info-c");
        }

        /// <summary>
        /// Warn (with the remote endpoint) whenever a Custom or Obsolete
        /// algorithm entry is actually negotiated. Aliases resolve at the
        /// severity of what they point to, so only Custom / Obsolete entries
        /// (which cannot be laundered through an alias) produce a warning.
        /// </summary>
        private void WarnIfHazmatNegotiated()
        {
            LogWarnOnTag(_keyExchangeTags, _exchangeContext.KeyExchange, "key exchange");
            LogWarnOnTag(_publicKeyTags, _exchangeContext.PublicKey, "host key");
            LogWarnOnTag(_encryptionTags, _exchangeContext.ClientEncryption, "encryption");
            LogWarnOnTag(_encryptionTags, _exchangeContext.ServerEncryption, "encryption");
            LogWarnOnTag(_hmacTags, _exchangeContext.ClientHmac, "MAC");
            LogWarnOnTag(_hmacTags, _exchangeContext.ServerHmac, "MAC");
            LogWarnOnTag(_compressionTags, _exchangeContext.ClientCompression, "compression");
            LogWarnOnTag(_compressionTags, _exchangeContext.ServerCompression, "compression");
        }

        private void LogWarnOnTag(IReadOnlyDictionary<string, HazmatAlgorithmTag> tags, string algorithm, string category)
        {
            if (!Log.IsEnabled(LogLevel.Warn))
                return;

            if (tags.TryGetValue(algorithm, out var tag)
                && (tag == HazmatAlgorithmTag.Custom || tag == HazmatAlgorithmTag.Obsolete))
            {
                string remote = _socket.RemoteEndPoint?.ToString() ?? "?";
                Log.Warn($"Session {remote} negotiated hazmat {category} algorithm '{algorithm}' ({tag}).");
            }
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

        private void HandleMessage(KeyExchangeDhInitMessage message)
        {
            var kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]();
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey](_hostKey[_exchangeContext.PublicKey]);
            var clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption]();
            var serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption]();
            var serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac]();
            var clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac]();

            var clientExchangeValue = message.E;
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, false);

            if (SessionId == null)
            {
                SessionId = exchangeHash;
                Log.Info($"Key exchange complete, session id {BitConverter.ToString(exchangeHash).Replace("-", "").Substring(0, 16)}...");
            }

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                F = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
        }

        private void HandleMessage(KeyExchangeECDhInitMessage message)
        {
            var kexAlg = _keyExchangeAlgorithms[_exchangeContext.KeyExchange]();
            var hostKeyAlg = _publicKeyAlgorithms[_exchangeContext.PublicKey](_hostKey[_exchangeContext.PublicKey]);
            var clientCipher = _encryptionAlgorithms[_exchangeContext.ClientEncryption]();
            var serverCipher = _encryptionAlgorithms[_exchangeContext.ServerEncryption]();
            var serverHmac = _hmacAlgorithms[_exchangeContext.ServerHmac]();
            var clientHmac = _hmacAlgorithms[_exchangeContext.ClientHmac]();

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
                Log.Info($"Key exchange complete, session id {BitConverter.ToString(exchangeHash).Replace("-", "").Substring(0, 16)}...");
            }

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeECDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                Q = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
        }

        private void HandleMessage(NewKeysMessage message)
        {
            // RFC 4253 7.3: send SSH_MSG_NEWKEYS before applying the new keys.
            // We deliberately send the server's NEWKEYS here (after receiving the
            // client's NEWKEYS) so that our server's NEWKEYS data segment piggybacks
            // the ACK for the client's NEWKEYS. Otherwise the client's NEWKEYS stays
            // un-ACKed and Nagle blocks the subsequent SERVICE_REQUEST until the
            // delayed-ACK timer fires (~40ms on Linux).
            Log.Debug("New keys applied.");
            SendMessageInternal(new NewKeysMessage());

            lock (_locker)
            {
                _inboundFlow = 0;
                _outboundFlow = 0;
                _algorithms = _exchangeContext.NewAlgorithms;
                _exchangeContext = null;
            }

            // RFC 8308 section 2.2: send SSH_MSG_EXT_INFO as the first message
            // under the new keys, before any blocked messages are flushed.
            // Only send when the client advertised "ext-info-c" in its KEXINIT.
            if (_clientAdvertisedExtInfo && _extensionsToSend.Count > 0)
            {
                SendMessageInternal(new ExtInfoMessage
                {
                    Extensions = new Dictionary<string, string>(_extensionsToSend)
                });
            }

            ContinueSendBlockedMessages();
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
        /// <paramref name="idle"/> interval. If the peer fails to answer
        /// MaxMissedProbes consecutive probes the session is torn down.
        /// Pass a non-positive value to disable probing. Calling this before
        /// the session is established is allowed; the timer starts immediately.
        /// </summary>
        public void ConfigureKeepalive(TimeSpan idle)
        {
            lock (_locker)
            {
                _keepaliveIdle = idle;

                if (idle <= TimeSpan.Zero)
                {
                    _keepaliveTimer?.Dispose();
                    _keepaliveTimer = null;
                    _missedProbes = 0;
                    Log.Debug("Keepalive probing disabled.");
                    return;
                }

                Log.Debug($"Keepalive probing enabled, idle threshold {idle}.");

                _lastActivity ??= Stopwatch.StartNew();

                // Period = idle: when idle has elapsed we start probing at the
                // same cadence. DueTime also idle so the first probe fires one
                // idle window after the last activity, not immediately.
                var due = (int)Math.Min(idle.TotalMilliseconds, int.MaxValue);
                if (_keepaliveTimer == null)
                    _keepaliveTimer = new Timer(KeepaliveTick, null, due, due);
                else
                    _keepaliveTimer.Change(due, due);
            }
        }

        private void KeepaliveTick(object state)
        {
            if (_disconnected || _socket == null)
                return;

            // Not idle long enough yet - peer is active, nothing to probe.
            if (_lastActivity?.Elapsed < _keepaliveIdle)
                return;

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
            if (service != null)
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
            // bytes), AES-GCM uses the 4-byte fixed_iv (RFC 5647 section 7.1). The
            // remaining 8 bytes of the GCM nonce are a per-packet counter owned
            // by GcmModeCryptoTransform.
            var clientCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.IVSize, sharedSecret, 'A');
            var serverCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.IVSize, sharedSecret, 'B');
            var clientCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.KeySize >> 3, sharedSecret, 'C');
            var serverCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.KeySize >> 3, sharedSecret, 'D');

            var clientEncryption = clientCipher.Cipher(clientCipherKey, clientCipherIV, false);
            var serverEncryption = serverCipher.Cipher(serverCipherKey, serverCipherIV, true);

            // AEAD (GCM) replaces the separate HMAC with an inline auth tag.
            // RFC 5647 section 6: the negotiated MAC name is still carried in KEX_INIT
            // and the MAC key is still derived for compatibility, but it MUST NOT
            // be used to authenticate packets - the GCM tag does that. We skip
            // deriving the MAC key for the AEAD direction entirely (nothing reads
            // ClientHmac/ServerHmac when the corresponding cipher IsAead), and
            // leave the HmacAlgorithm slots null so any accidental use fails loud.
            HmacAlgorithm clientHmacAlg = null;
            HmacAlgorithm serverHmacAlg = null;
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

            var algorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                PublicKey = hostKeyAlg,
                ClientEncryption = clientEncryption,
                ServerEncryption = serverEncryption,
                ClientHmac = clientHmacAlg,
                ServerHmac = serverHmacAlg,
                ClientCompression = _compressionAlgorithms[_exchangeContext.ClientCompression](),
                ServerCompression = _compressionAlgorithms[_exchangeContext.ServerCompression](),
                ClientHmacIsEtm = clientHmac.IsEtm,
                ServerHmacIsEtm = serverHmac.IsEtm,
            };

            return algorithms;
        }

        private byte[] ComputeEncryptionKey(KexAlgorithm kexAlg, byte[] exchangeHash, int blockSize, byte[] sharedSecret, char letter)
        {
            var keyBuffer = new byte[blockSize];
            var keyBufferIndex = 0;
            var currentHashLength = 0;
            byte[] currentHash = null;

            while (keyBufferIndex < blockSize)
            {
                var writer = new SshDataWriter();
                // Hybrid PQ/T methods feed K into the KDF as an SSH string;
                // classical methods use the RFC 4253 mpint encoding.
                if (kexAlg.SharedSecretIsString)
                    writer.WriteBinary(sharedSecret);
                else
                    writer.WriteMpint(sharedSecret);
                writer.WriteBytes(exchangeHash);

                if (currentHash == null)
                {
                    writer.Write((byte)letter);
                    writer.WriteBytes(SessionId);
                }
                else
                {
                    writer.WriteBytes(currentHash);
                }

                currentHash = kexAlg.ComputeHash(writer.ToByteArray());

                currentHashLength = Math.Min(currentHash.Length, blockSize - keyBufferIndex);
                Array.Copy(currentHash, 0, keyBuffer, keyBufferIndex, currentHashLength);

                keyBufferIndex += currentHashLength;
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
            return mac.SequenceEqual(expected);
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

        private class Algorithms
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
