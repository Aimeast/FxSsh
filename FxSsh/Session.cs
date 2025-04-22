using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Services;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace FxSsh
{
    public class Session
    {
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        internal const int MaximumSshPacketSize = LocalChannelDataPacketSize;
        internal const int InitialLocalWindowSize = LocalChannelDataPacketSize * 32;
        internal const int LocalChannelDataPacketSize = 1024 * 32;

        private static readonly Dictionary<byte, Type> _messagesMetadata;
        internal static readonly Dictionary<string, Func<KexAlgorithm>> _keyExchangeAlgorithms = [];
        internal static readonly Dictionary<string, Func<string, PublicKeyAlgorithm>> _publicKeyAlgorithms = [];
        internal static readonly Dictionary<string, Func<CipherInfo>> _encryptionAlgorithms = [];
        internal static readonly Dictionary<string, Func<HmacInfo>> _hmacAlgorithms = [];
        internal static readonly Dictionary<string, Func<CompressionAlgorithm>> _compressionAlgorithms = [];

        private readonly object _locker = new();
        private readonly Socket _socket;
#if DEBUG
        private readonly TimeSpan _timeout = TimeSpan.FromDays(1);
#else
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
#endif
        private readonly Dictionary<string, string> _hostKey;

        private uint _outboundPacketSequence;
        private uint _inboundPacketSequence;
        private uint _outboundFlow;
        private uint _inboundFlow;
        private Algorithms _algorithms = null;
        private ExchangeContext _exchangeContext = null;
        private List<SshService> _services = [];
        private ConcurrentQueue<Message> _blockedMessages = new();
        private EventWaitHandle _hasBlockedMessagesWaitHandle = new ManualResetEvent(true);

        public string ServerVersion { get; private set; }
        public string ClientVersion { get; private set; }
        public byte[] SessionId { get; private set; }
        public T GetService<T>() where T : SshService
        {
            return (T)_services.FirstOrDefault(x => x is T);
        }

        static Session()
        {
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp256", () => new EcdhKex("nistp256"));
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp384", () => new EcdhKex("nistp384"));
            _keyExchangeAlgorithms.Add("ecdh-sha2-nistp521", () => new EcdhKex("nistp521"));
            _keyExchangeAlgorithms.Add("diffie-hellman-group18-sha512", () => new DiffieHellmanKex(512, 8192));
            _keyExchangeAlgorithms.Add("diffie-hellman-group16-sha512", () => new DiffieHellmanKex(512, 4096));
            _keyExchangeAlgorithms.Add("diffie-hellman-group14-sha256", () => new DiffieHellmanKex(256, 2048));

            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp256", x => new EcdsaKey("nistp256", x));
            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp384", x => new EcdsaKey("nistp384", x));
            _publicKeyAlgorithms.Add("ecdsa-sha2-nistp521", x => new EcdsaKey("nistp521", x));
            _publicKeyAlgorithms.Add("rsa-sha2-256", x => new RsaKey(256, x));
            _publicKeyAlgorithms.Add("rsa-sha2-512", x => new RsaKey(512, x));

            _encryptionAlgorithms.Add("aes128-ctr", () => new CipherInfo(Aes.Create(), 128, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes192-ctr", () => new CipherInfo(Aes.Create(), 192, CipherModeEx.CTR));
            _encryptionAlgorithms.Add("aes256-ctr", () => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR));

            _hmacAlgorithms.Add("hmac-sha2-256", () => new HmacInfo(new HMACSHA256(), 256));
            _hmacAlgorithms.Add("hmac-sha2-512", () => new HmacInfo(new HMACSHA512(), 512));

            _compressionAlgorithms.Add("none", () => new NoCompression());

            _messagesMetadata = (from t in typeof(Message).Assembly.GetTypes()
                                 let attrib = (MessageAttribute)t.GetCustomAttributes(typeof(MessageAttribute), false).FirstOrDefault()
                                 where attrib != null
                                 select new { attrib.Number, Type = t })
                                 .ToDictionary(x => x.Number, x => x.Type);
        }

        public Session(Socket socket, Dictionary<string, string> hostKey, string serverBanner)
        {
            Contract.Requires(socket != null);
            Contract.Requires(hostKey != null);

            _socket = socket;
            _hostKey = hostKey.ToDictionary(s => s.Key, s => s.Value);
            ServerVersion = serverBanner;
        }

        public event EventHandler<EventArgs> Disconnected;

        public event EventHandler<SshService> ServiceRegistered;

        public event EventHandler<KeyExchangeArgs> KeysExchanged;

        internal void EstablishConnection()
        {
            if (!_socket.Connected)
            {
                return;
            }

            SetSocketOptions();

            SocketWriteProtocolVersion();
            ClientVersion = SocketReadProtocolVersion();
            if (!Regex.IsMatch(ClientVersion, "SSH-2.0-.+"))
            {
                throw new SshConnectionException(
                    string.Format("Not supported for client SSH version {0}. This server only supports SSH v2.0.", ClientVersion),
                    DisconnectReason.ProtocolVersionNotSupported);
            }

            ConsiderReExchange(true);

            try
            {
                while (_socket != null && _socket.Connected)
                {
                    var message = ReceiveMessage();
                    if (message is UnknownMessage unknownMessage)
                        SendMessage(unknownMessage.MakeUnimplementedMessage());
                    else
                        HandleMessageCore(message);
                }
            }
            finally
            {
                foreach (var service in _services)
                {
                    service.CloseService();
                }
            }
        }

        public void Disconnect(DisconnectReason reason = DisconnectReason.ByApplication, string description = "Connection terminated by the server.")
        {
            if (reason == DisconnectReason.ByApplication)
            {
                var message = new DisconnectMessage(reason, description);
                TrySendMessage(message);
            }

            try
            {
                _socket.Shutdown(SocketShutdown.Both);
                _socket.Close();
                _socket.Dispose();
            }
            catch { }

            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        #region Socket operations
        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _socket.LingerState = new LingerOption(enable: false, seconds: 0);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
            _socket.ReceiveTimeout = (int)_timeout.TotalMilliseconds;
        }

        private string SocketReadProtocolVersion()
        {
            // http://tools.ietf.org/html/rfc4253#section-4.2
            var buffer = new byte[255];
            var dummy = new byte[255];
            var pos = 0;
            var len = 0;

            while (pos < buffer.Length)
            {
                var ar = _socket.BeginReceive(buffer, pos, buffer.Length - pos, SocketFlags.Peek, null, null);
                WaitHandle(ar);
                len = _socket.EndReceive(ar);

                if (len == 0)
                {
                    throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
                }

                for (var i = 0; i < len; i++, pos++)
                {
                    if (pos > 0 && buffer[pos - 1] == CarriageReturn && buffer[pos] == LineFeed)
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos - 1);
                    }
                    else if (pos > 0 && buffer[pos] == LineFeed) // Non-RFC case
                    {
                        _socket.Receive(dummy, 0, i + 1, SocketFlags.None);
                        return Encoding.ASCII.GetString(buffer, 0, pos);
                    }
                }
                _socket.Receive(dummy, 0, len, SocketFlags.None);
            }
            throw new SshConnectionException("Could't read the protocal version", DisconnectReason.ProtocolError);
        }

        private void SocketWriteProtocolVersion()
        {
            SocketWrite(Encoding.ASCII.GetBytes(ServerVersion + "\r\n"));
        }

        private byte[] SocketRead(int length)
        {
            var pos = 0;
            var buffer = new byte[length];

            var msSinceLastData = 0;

            while (pos < length)
            {
                try
                {
                    var ar = _socket.BeginReceive(buffer, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    var len = _socket.EndReceive(ar);
                    if (!_socket.Connected)
                    {
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                    }

                    if (len == 0 && _socket.Available == 0)
                    {
                        if (msSinceLastData >= _timeout.TotalMilliseconds)
                        {
                            throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                        }

                        msSinceLastData += 50;
                        Thread.Sleep(50);
                    }
                    else
                    {
                        msSinceLastData = 0;
                    }

                    pos += len;
                }
                catch (SocketException exp)
                {
                    if (exp.SocketErrorCode == SocketError.WouldBlock ||
                        exp.SocketErrorCode == SocketError.IOPending ||
                        exp.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        Thread.Sleep(30);
                    }
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
            }

            return buffer;
        }

        private void SocketWrite(byte[] data)
        {
            var pos = 0;
            var length = data.Length;

            while (pos < length)
            {
                try
                {
                    var ar = _socket.BeginSend(data, pos, length - pos, SocketFlags.None, null, null);
                    WaitHandle(ar);
                    pos += _socket.EndSend(ar);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.WouldBlock ||
                        ex.SocketErrorCode == SocketError.IOPending ||
                        ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        Thread.Sleep(30);
                    }
                    else
                        throw new SshConnectionException("Connection lost", DisconnectReason.ConnectionLost);
                }
            }
        }

        private void WaitHandle(IAsyncResult ar)
        {
            if (!ar.AsyncWaitHandle.WaitOne(_timeout))
                throw new SshConnectionException(string.Format("Socket operation has timed out after {0:F0} milliseconds.",
                    _timeout.TotalMilliseconds),
                    DisconnectReason.ConnectionLost);
        }
        #endregion

        #region Message operations
        private Message ReceiveMessage()
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ClientEncryption.BlockBytesSize) : 8);
            var firstBlock = SocketRead(blockSize);
            if (useAlg)
                firstBlock = _algorithms.ClientEncryption.Transform(firstBlock);

            var packetLength = firstBlock[0] << 24 | firstBlock[1] << 16 | firstBlock[2] << 8 | firstBlock[3];
            var paddingLength = firstBlock[4];
            var bytesToRead = packetLength - blockSize + 4;

            var followingBlocks = SocketRead(bytesToRead);
            if (useAlg && followingBlocks.Length > 0)
                followingBlocks = _algorithms.ClientEncryption.Transform(followingBlocks);

            var fullPacket = new ReadOnlyMemory<byte>([.. firstBlock, .. followingBlocks]);
            var data = fullPacket[5..(packetLength - paddingLength + 5)];
            if (useAlg)
            {
                var clientMac = SocketRead(_algorithms.ClientHmac.DigestLength);
                var mac = ComputeHmac(_algorithms.ClientHmac, fullPacket, _inboundPacketSequence);
                if (!clientMac.SequenceEqual(mac))
                {
                    throw new SshConnectionException("Invalid MAC", DisconnectReason.MacError);
                }

                data = _algorithms.ClientCompression.Decompress(data);
            }

            var typeNumber = data.Span[0];
            var implemented = _messagesMetadata.ContainsKey(typeNumber);
            var message = implemented
                ? (Message)Activator.CreateInstance(_messagesMetadata[typeNumber])
                : new UnknownMessage { SequenceNumber = _inboundPacketSequence, UnknownMessageType = typeNumber };

            if (implemented)
                message.Load(data);

            lock (_locker)
            {
                _inboundPacketSequence++;
                _inboundFlow += (uint)packetLength;
            }

            ConsiderReExchange();

            return message;
        }

        internal void SendMessage(Message message)
        {
            Contract.Requires(message != null);

            if (_exchangeContext != null
                && message.MessageType > 4 && (message.MessageType < 20 || message.MessageType > 49))
            {
                _blockedMessages.Enqueue(message);
                return;
            }

            _hasBlockedMessagesWaitHandle.WaitOne();
            lock (_locker)
                SendMessageInternal(message);
        }

        private void SendMessageInternal(Message message)
        {
            var useAlg = _algorithms != null;

            var blockSize = (byte)(useAlg ? Math.Max(8, _algorithms.ServerEncryption.BlockBytesSize) : 8);
            var payload = message.GetPacket();
            if (useAlg)
                payload = _algorithms.ServerCompression.Compress(payload);

            // http://tools.ietf.org/html/rfc4253
            // 6.  Binary Packet Protocol
            // the total length of (packet_length || padding_length || payload || padding)
            // is a multiple of the cipher block size or 8,
            // padding length must between 4 and 255 bytes.
            var paddingLength = (byte)(blockSize - (payload.Length + 5) % blockSize);
            if (paddingLength < 4)
                paddingLength += blockSize;

            var packetLength = (uint)payload.Length + paddingLength + 1;

            var padding = new byte[paddingLength];
            RandomNumberGenerator.Fill(padding);

            payload = new SshDataWriter(5 + payload.Length + padding.Length)
                .Write(packetLength)
                .Write(paddingLength)
                .WriteBytes(payload)
                .WriteBytes(padding)
                .ToByteArray();

            if (useAlg)
            {
                var mac = ComputeHmac(_algorithms.ServerHmac, payload, _outboundPacketSequence);
                payload = _algorithms.ServerEncryption.Transform(payload).Concat(mac).ToArray();
            }

            SocketWrite(payload);

            lock (_locker)
            {
                _outboundPacketSequence++;
                _outboundFlow += packetLength;
            }

            ConsiderReExchange();
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
            Contract.Requires(message != null);

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
            var message = new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = [.. _keyExchangeAlgorithms.Keys],
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
                Reserved = 0
            };

            return message;
        }
        #endregion

        #region Handle messages
        private void HandleMessageCore(Message message)
        {
            this.HandleMessage((dynamic)message);
        }

        private void HandleMessage(DisconnectMessage message)
        {
            Disconnect(message.ReasonCode, message.Description);
        }

        private void HandleMessage(KeyExchangeInitMessage message)
        {
            ConsiderReExchange(true);

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
                ServerHostKeyAlgorithms = message.ServerHostKeyAlgorithms,
                CanSendExtInfo = message.CanSendExtInfo
            });

            _exchangeContext.KeyExchange = ChooseAlgorithm([.. _keyExchangeAlgorithms.Keys], message.KeyExchangeAlgorithms);
            _exchangeContext.PublicKey = ChooseAlgorithm(_publicKeyAlgorithms.Keys.Intersect(_hostKey.Keys).ToArray(), message.ServerHostKeyAlgorithms);
            _exchangeContext.ClientEncryption = ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsClientToServer);
            _exchangeContext.ServerEncryption = ChooseAlgorithm([.. _encryptionAlgorithms.Keys], message.EncryptionAlgorithmsServerToClient);
            _exchangeContext.ClientHmac = ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsClientToServer);
            _exchangeContext.ServerHmac = ChooseAlgorithm([.. _hmacAlgorithms.Keys], message.MacAlgorithmsServerToClient);
            _exchangeContext.ClientCompression = ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsClientToServer);
            _exchangeContext.ServerCompression = ChooseAlgorithm([.. _compressionAlgorithms.Keys], message.CompressionAlgorithmsServerToClient);
            _exchangeContext.CanSendExtInfo = message.CanSendExtInfo;

            _exchangeContext.ClientKexInitPayload = message.GetPacket();
        }

        private void HandleMessage(KeyExchangeXInitMessage message)
        {
            switch (_exchangeContext.PublicKey)
            {
                case "rsa-sha2-256":
                case "rsa-sha2-512":
                    message = Message.LoadFrom<KeyExchangeDhInitMessage>(message);
                    break;
                case "ecdsa-sha2-nistp256":
                case "ecdsa-sha2-nistp384":
                case "ecdsa-sha2-nistp521":
                    message = Message.LoadFrom<KeyExchangeECDhInitMessage>(message);
                    break;
                default:
                    throw new InvalidOperationException();
            }
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
                SessionId = exchangeHash;

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                F = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
            SendMessage(new NewKeysMessage());
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
            var serverExchangeValue = kexAlg.CreateKeyExchange();
            var sharedSecret = kexAlg.DecryptKeyExchange(clientExchangeValue);
            var hostKeyAndCerts = hostKeyAlg.CreateKeyAndCertificatesData();
            var exchangeHash = ComputeExchangeHash(kexAlg, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret, true);

            if (SessionId == null)
                SessionId = exchangeHash;

            _exchangeContext.NewAlgorithms = ComputeEncryption(kexAlg, hostKeyAlg, exchangeHash, clientCipher, serverCipher, clientHmac, serverHmac, sharedSecret);

            var reply = new KeyExchangeECDhReplyMessage
            {
                HostKey = hostKeyAndCerts,
                Q = serverExchangeValue,
                Signature = hostKeyAlg.CreateSignatureData(exchangeHash),
            };

            SendMessage(reply);
            SendMessage(new NewKeysMessage());
        }

        private void HandleMessage(NewKeysMessage message)
        {
            if (_exchangeContext.CanSendExtInfo)
            {
                var extInfo = new ExtInfoMessage();
                extInfo.Extensions.Add(ExtInfoMessage.ServerSignatureAlgorithms, string.Join(",", _publicKeyAlgorithms.Keys));
                SendMessage(extInfo);
            }
            
            _hasBlockedMessagesWaitHandle.Reset();

            lock (_locker)
            {
                _inboundFlow = 0;
                _outboundFlow = 0;
                _algorithms = _exchangeContext.NewAlgorithms;
                _exchangeContext = null;
            }

            ContinueSendBlockedMessages();
            _hasBlockedMessagesWaitHandle.Set();
        }

        private void HandleMessage(UnimplementedMessage message)
        {
            // Nothing to do here
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

        private string ChooseAlgorithm(string[] serverAlgorithms, string[] clientAlgorithms)
        {
            foreach (var client in clientAlgorithms)
                foreach (var server in serverAlgorithms)
                    if (client == server)
                        return client;

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
            writer.WriteMpint(sharedSecret);
            return kexAlg.ComputeHash(writer.ToByteArray());
        }

        private Algorithms ComputeEncryption(KexAlgorithm kexAlg, PublicKeyAlgorithm hostKeyAlg, byte[] exchangeHash, CipherInfo clientCipher, CipherInfo serverCipher, HmacInfo clientHmac, HmacInfo serverHmac, byte[] sharedSecret)
        {
            var clientCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.BlockSize >> 3, sharedSecret, 'A');
            var serverCipherIV = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.BlockSize >> 3, sharedSecret, 'B');
            var clientCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientCipher.KeySize >> 3, sharedSecret, 'C');
            var serverCipherKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverCipher.KeySize >> 3, sharedSecret, 'D');
            var clientHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, clientHmac.KeySize >> 3, sharedSecret, 'E');
            var serverHmacKey = ComputeEncryptionKey(kexAlg, exchangeHash, serverHmac.KeySize >> 3, sharedSecret, 'F');

            var algorithms = new Algorithms
            {
                KeyExchange = kexAlg,
                PublicKey = hostKeyAlg,
                ClientEncryption = clientCipher.Cipher(clientCipherKey, clientCipherIV, false),
                ServerEncryption = serverCipher.Cipher(serverCipherKey, serverCipherIV, true),
                ClientHmac = clientHmac.Hmac(clientHmacKey),
                ServerHmac = serverHmac.Hmac(serverHmacKey),
                ClientCompression = _compressionAlgorithms[_exchangeContext.ClientCompression](),
                ServerCompression = _compressionAlgorithms[_exchangeContext.ServerCompression](),
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
                var writer = new SshDataWriter()
                    .WriteMpint(sharedSecret)
                    .WriteBytes(exchangeHash);

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

        private byte[] ComputeHmac(HmacAlgorithm alg, ReadOnlyMemory<byte> payload, uint seq)
        {
            var bytes = new SshDataWriter(4 + payload.Length)
                .Write(seq)
                .WriteBytes(payload)
                .ToByteArray();

            return alg.ComputeHash(bytes);
        }

        internal SshService RegisterService(string serviceName, UserAuthArgs auth = null)
        {
            Contract.Requires(serviceName != null);

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
            public bool CanSendExtInfo;
        }
    }
}
