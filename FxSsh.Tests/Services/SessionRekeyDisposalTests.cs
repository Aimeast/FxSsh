using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Algorithms;
using FxSsh.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Deterministic disposal of the negotiated cipher/MAC objects: a real
    /// in-memory client completes the SSH key exchange, triggers a rekey and
    /// tears the session down, and the test asserts the server-side algorithm
    /// instances were disposed at exactly the claimed points - after the
    /// NEWKEYS swap and after every protocol pump stopped.
    /// </summary>
    [TestClass]
    public sealed class SessionRekeyDisposalTests
    {
        [TestMethod]
        public async Task Rekey_disposes_the_previous_algorithm_set()
        {
            var (session, client, clientSocket, serverTask) = await CreateEstablishedSessionAsync();
            try
            {
                var first = GetClientEncryption(session);
                Assert.IsFalse(IsDisposed(first));

                client.Rekey();

                var second = GetClientEncryption(session);
                Assert.AreNotSame(first, second, "the NEWKEYS swap must install a fresh algorithm set");
                Assert.IsFalse(IsDisposed(second));
                Assert.IsTrue(client.ExchangeGlobalRequest(), "encrypted traffic must still flow after the rekey");

                // The server NEWKEYS frame is queued before the swap and the
                // disposal that follows it, so reading the frame does not yet
                // prove the old set was released. The answered round trip
                // does: the single message loop can only respond after the
                // NEWKEYS handler (swap + dispose) completed, and the session
                // is still alive, so the teardown cannot be the disposer.
                Assert.IsTrue(IsDisposed(first), "the previous cipher must be disposed deterministically on rekey");
            }
            finally
            {
                clientSocket.Dispose();
                client.Dispose();
                await WaitForTeardownAsync(session, serverTask);
            }
        }

        [TestMethod]
        public async Task Teardown_disposes_the_negotiated_algorithm_set()
        {
            var (session, client, clientSocket, serverTask) = await CreateEstablishedSessionAsync();
            // Capture before teardown: ReleaseAlgorithms clears the field, so
            // the captured instance is the only handle left to assert on.
            var cipher = GetClientEncryption(session);
            try
            {
                Assert.IsFalse(IsDisposed(cipher));
                Assert.IsTrue(client.ExchangeGlobalRequest(), "encrypted traffic must flow after the handshake");
            }
            finally
            {
                clientSocket.Dispose();
                client.Dispose();
                await WaitForTeardownAsync(session, serverTask);
            }

            Assert.IsTrue(IsDisposed(cipher), "the negotiated cipher must be disposed once every pump stopped");
        }

        private static async Task<(Session Session, SshTestClient Client, Socket ClientSocket, Task ServerTask)> CreateEstablishedSessionAsync()
        {
            // Surface the server side of the handshake on the test output.
            FxSsh.Logging.Log.Configure(new FxSsh.Logging.LogOptions
            {
                MinLevel = FxSsh.Logging.LogLevel.Trace,
                Sink = new FxSsh.Logging.ConsoleLogSink(),
            });

            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            clientSocket.Connect(listener.LocalEndPoint!);
            var serverSocket = listener.Accept();

            var hostKeyPem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
            var session = new Session(serverSocket, new Dictionary<string, string>
            {
                ["ecdsa-sha2-nistp256"] = hostKeyPem,
            }, "SSH-2.0-Unit");

            var serverError = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var serverTask = session.StartAsync();
            _ = serverTask.ContinueWith(
                t => serverError.TrySetResult(t.Exception?.GetBaseException()?.ToString() ?? "unknown"),
                TaskContinuationOptions.OnlyOnFaulted);

            var client = new SshTestClient(clientSocket, hostKeyPem, serverError);
            try
            {
                client.Handshake();
            }
            catch (Exception ex)
            {
                // Wait briefly for the server pump to surface its exception.
                client.Dispose();
                Assert.Fail($"the client handshake failed ({ex}); server side: {serverError.Task}");
            }

            return (session, client, clientSocket, serverTask);
        }

        private static async Task WaitForTeardownAsync(Session session, Task serverTask)
        {
            // Returning from StartAsync is the authoritative end signal: its
            // finally block (which disposes the negotiated algorithms) has
            // then run, unlike the Disconnected event that fires earlier.
            session.Disconnect();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            await session.DisconnectAsync();
        }

        private static object GetAlgorithms(Session session)
            => session.GetType().GetField("_algorithms", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(session)!;

        private static EncryptionAlgorithm GetClientEncryption(Session session)
        {
            var algorithms = GetAlgorithms(session);
            return (EncryptionAlgorithm)algorithms.GetType()
                .GetField("ClientEncryption", BindingFlags.Public | BindingFlags.Instance)!
                .GetValue(algorithms)!;
        }

        private static bool IsDisposed(EncryptionAlgorithm algorithm)
            => (bool)algorithm.GetType().GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(algorithm)!;

        /// <summary>
        /// A minimal SSH-2.0 client speaking diffie-hellman-group14-sha256,
        /// aes256-ctr and hmac-sha2-256 over an in-memory socket pair. Only
        /// what the tests above need: version exchange, KEX, NEWKEYS, a
        /// rekey, and SSH_MSG_IGNORE interop.
        /// </summary>
        private sealed class SshTestClient : IDisposable
        {
            private const string ClientVersion = "SSH-2.0-UnitClient";
            private const int CipherKeyLength = 32;    // aes256
            private const int CipherIVLength = 16;     // AES block
            private const int MacLength = 32;          // hmac-sha2-256
            private const byte KexInitType = 20;
            private const byte NewKeysType = 21;

            private readonly NetworkStream _stream;
            private readonly string _hostKeyPem;
            private readonly TaskCompletionSource<string> _serverError;
            private string _serverVersion = null!;
            private byte[] _sessionId = null!;
            private EncryptionAlgorithm _outCipher = null!;
            private EncryptionAlgorithm _inCipher = null!;
            private HMACSHA256 _outMac = null!;
            private HMACSHA256 _inMac = null!;
            private uint _outSeq;
            private uint _inSeq;
            private bool _outEncrypted;
            private bool _inEncrypted;

            public SshTestClient(Socket socket, string hostKeyPem, TaskCompletionSource<string> serverError)
            {
                _stream = new NetworkStream(socket, ownsSocket: false)
                {
                    ReadTimeout = 20000,
                    WriteTimeout = 20000,
                };
                _hostKeyPem = hostKeyPem;
                _serverError = serverError;
            }

            public void Handshake()
            {
                WriteBytes(Encoding.ASCII.GetBytes(ClientVersion + "\r\n"));
                _serverVersion = ReadLine();

                var dh = new DiffieHellmanKex(256, 2048);
                var (exchangeHash, sharedSecret) = RunKeyExchange(BuildKexInitPayload(), dh);
                _sessionId = exchangeHash;

                // Our NEWKEYS goes out without encryption; switch the outbound
                // side immediately, as RFC 4253 section 7.3 requires.
                WritePacket([NewKeysType]);
                InstallOutboundKeys(dh, sharedSecret, exchangeHash);

                // The server's NEWKEYS is still plaintext; switch inbound after.
                var serverNewKeys = ReadPacket();
                Assert.AreEqual(NewKeysType, serverNewKeys[0], "expected the server NEWKEYS");
                InstallInboundKeys(dh, sharedSecret, exchangeHash);
            }

            public void Rekey()
            {
                var dh = new DiffieHellmanKex(256, 2048);
                var (exchangeHash, sharedSecret) = RunKeyExchange(BuildKexInitPayload(), dh);

                // Our NEWKEYS goes out under the old keys; swap right after.
                WritePacket([NewKeysType]);
                InstallOutboundKeys(dh, sharedSecret, exchangeHash);

                // The server's NEWKEYS still arrives under the old keys.
                var serverNewKeys = ReadPacket();
                Assert.AreEqual(NewKeysType, serverNewKeys[0], "expected the server NEWKEYS");
                InstallInboundKeys(dh, sharedSecret, exchangeHash);
            }

            /// <summary>
            /// Sends a global request that wants a reply and consumes the
            /// server's encrypted answer, proving both directions of the
            /// current key set. Unknown request names answer
            /// SSH_MSG_REQUEST_FAILURE (82).
            /// </summary>
            public bool ExchangeGlobalRequest()
            {
                using (var writer = new SshDataWriter())
                {
                    writer.Write((byte)80);   // SSH_MSG_GLOBAL_REQUEST
                    writer.Write("fxssh-test@unit", Encoding.ASCII);
                    writer.Write(true);
                    WritePacket(writer.ToByteArray());
                }

                var reply = ReadPacket();
                var ok = reply[0] is 81 or 82;   // REQUEST_SUCCESS / REQUEST_FAILURE
                Assert.IsTrue(ok, $"expected a global request reply, got {reply[0]}");
                return ok;
            }

            private byte[] BuildKexInitPayload()
            {
                return new KeyExchangeInitMessage
                {
                    KeyExchangeAlgorithms = ["diffie-hellman-group14-sha256"],
                    ServerHostKeyAlgorithms = ["ecdsa-sha2-nistp256"],
                    EncryptionAlgorithmsClientToServer = ["aes256-ctr"],
                    EncryptionAlgorithmsServerToClient = ["aes256-ctr"],
                    MacAlgorithmsClientToServer = ["hmac-sha2-256"],
                    MacAlgorithmsServerToClient = ["hmac-sha2-256"],
                    CompressionAlgorithmsClientToServer = ["none"],
                    CompressionAlgorithmsServerToClient = ["none"],
                    LanguagesClientToServer = [""],
                    LanguagesServerToClient = [""],
                }.GetPacket();
            }

            private (byte[] ExchangeHash, byte[] SharedSecret) RunKeyExchange(
                byte[] clientKexInitPayload, DiffieHellmanKex dh)
            {
                // Send ours first; the server's KEXINIT was already sent
                // before it (initial exchange) or answers ours (rekey).
                WritePacket(clientKexInitPayload);
                var serverKexInitPayload = ReadPacket();
                Assert.AreEqual(KexInitType, serverKexInitPayload[0], "expected the server KEXINIT");

                var e = dh.CreateKeyExchange();
                using (var initWriter = new SshDataWriter())
                {
                    initWriter.Write((byte)KeyExchangeXInitMessage.MessageNumber);
                    initWriter.WriteMpint(e);
                    WritePacket(initWriter.ToByteArray());
                }

                var replyPayload = ReadPacket();
                if (replyPayload[0] == 1)
                {
                    // SSH_MSG_DISCONNECT: surface the server-side reason in
                    // the failure message instead of a confusing type error.
                    var reason = (uint)(replyPayload[1] << 24 | replyPayload[2] << 16
                        | replyPayload[3] << 8 | replyPayload[4]);
                    var descriptionLength = replyPayload[5] << 24 | replyPayload[6] << 16
                        | replyPayload[7] << 8 | replyPayload[8];
                    var description = Encoding.ASCII.GetString(replyPayload, 9, descriptionLength);
                    var serverStack = _serverError.Task.IsCompleted ? _serverError.Task.Result : "not observed";
                    Assert.Fail($"the server disconnected during key exchange: reason={reason}, " +
                        $"description='{description}', server exception: {serverStack}");
                }

                // KEXDH_REPLY payload: string K_S || mpint f || string signature.
                // Parsed manually: Message.Load dispatches through the type
                // factory, which materialises the un-parsed base class.
                var reader = new SshDataReader(replyPayload);
                reader.ReadBytes(1);   // message number
                var hostKeyBlob = reader.ReadBinary();
                var f = reader.ReadMpint();
                var signature = reader.ReadBinary();

                var sharedSecret = dh.DecryptKeyExchange(f);
                var exchangeHash = ComputeExchangeHash(dh, hostKeyBlob, e, f, sharedSecret,
                    clientKexInitPayload, serverKexInitPayload);

                Assert.IsTrue(VerifyHostKeySignature(hostKeyBlob, signature, exchangeHash),
                    "the host key signature must verify");
                return (exchangeHash, sharedSecret);
            }

            private byte[] ComputeExchangeHash(KexAlgorithm dh, byte[] hostKeyBlob, byte[] e, byte[] f, byte[] k,
                byte[] clientKexInitPayload, byte[] serverKexInitPayload)
            {
                using var writer = new SshDataWriter();
                writer.Write(ClientVersion, Encoding.ASCII);
                writer.Write(_serverVersion, Encoding.ASCII);
                writer.WriteBinary(clientKexInitPayload);
                writer.WriteBinary(serverKexInitPayload);
                writer.WriteBinary(hostKeyBlob);
                writer.WriteMpint(e);
                writer.WriteMpint(f);
                writer.WriteMpint(k);
                return dh.ComputeHash(writer.ToByteArray());
            }

            private bool VerifyHostKeySignature(byte[] hostKeyBlob, byte[] signature, byte[] exchangeHash)
            {
                var key = new EcdsaKey("nistp256", _hostKeyPem);
                try
                {
                    key.LoadKeyAndCertificatesData(hostKeyBlob);
                    var raw = key.GetSignature(signature);
                    return key.VerifyData(exchangeHash, raw);
                }
                finally
                {
                    key.Dispose();
                }
            }

            private void InstallOutboundKeys(KexAlgorithm dh, byte[] sharedSecret, byte[] exchangeHash)
            {
                _outCipher?.Dispose();
                _outMac?.Dispose();
                _outCipher = new EncryptionAlgorithm(
                    Aes.Create(), 256, CipherModeEx.CTR,
                    Session.DeriveKey(dh, exchangeHash, CipherKeyLength, sharedSecret, 'C', _sessionId),
                    Session.DeriveKey(dh, exchangeHash, CipherIVLength, sharedSecret, 'A', _sessionId),
                    isEncryption: true);
                _outMac = new HMACSHA256(Session.DeriveKey(dh, exchangeHash, MacLength, sharedSecret, 'E', _sessionId));
                _outEncrypted = true;
            }

            private void InstallInboundKeys(KexAlgorithm dh, byte[] sharedSecret, byte[] exchangeHash)
            {
                _inCipher?.Dispose();
                _inMac?.Dispose();
                _inCipher = new EncryptionAlgorithm(
                    Aes.Create(), 256, CipherModeEx.CTR,
                    Session.DeriveKey(dh, exchangeHash, CipherKeyLength, sharedSecret, 'D', _sessionId),
                    Session.DeriveKey(dh, exchangeHash, CipherIVLength, sharedSecret, 'B', _sessionId),
                    isEncryption: false);
                _inMac = new HMACSHA256(Session.DeriveKey(dh, exchangeHash, MacLength, sharedSecret, 'F', _sessionId));
                _inEncrypted = true;
            }

            private void WritePacket(byte[] payload)
            {
                var block = _outEncrypted ? 16 : 8;
                var padding = block - ((payload.Length + 5) % block);
                if (padding < 4)
                    padding += block;
                var packetLength = payload.Length + padding + 1;

                var plain = new byte[4 + packetLength];
                plain[0] = (byte)(packetLength >> 24);
                plain[1] = (byte)(packetLength >> 16);
                plain[2] = (byte)(packetLength >> 8);
                plain[3] = (byte)packetLength;
                plain[4] = (byte)padding;
                payload.CopyTo(plain, 5);

                if (_outEncrypted)
                {
                    var mac = _outMac.ComputeHash(SeqInput(_outSeq, plain));
                    var cipherText = new byte[plain.Length];
                    _outCipher.Transform(plain, plain.Length, cipherText);
                    WriteBytes(cipherText);
                    WriteBytes(mac);
                }
                else
                {
                    WriteBytes(plain);
                }

                _outSeq++;
            }

            private byte[] ReadPacket()
            {
                var block = _inEncrypted ? 16 : 8;
                var first = ReadExactly(block);
                byte[] plainHead;
                if (_inEncrypted)
                {
                    plainHead = new byte[block];
                    _inCipher.Transform(first, 0, block, plainHead, 0);
                }
                else
                {
                    plainHead = first;
                }

                var packetLength = plainHead[0] << 24 | plainHead[1] << 16 | plainHead[2] << 8 | plainHead[3];
                var rest = ReadExactly(packetLength + 4 - block);
                byte[] decryptedRest;
                if (_inEncrypted && rest.Length > 0)
                {
                    // A minimum-size packet is exactly one cipher block; the
                    // remainder is then empty and must skip the transform
                    // (TransformBlock rejects a zero count).
                    decryptedRest = new byte[rest.Length];
                    _inCipher.Transform(rest, 0, rest.Length, decryptedRest, 0);
                }
                else
                {
                    decryptedRest = rest;
                }

                var plain = new byte[4 + packetLength];
                Array.Copy(plainHead, plain, block);
                Array.Copy(decryptedRest, 0, plain, block, decryptedRest.Length);

                if (_inEncrypted)
                {
                    var mac = ReadExactly(MacLength);
                    var expected = _inMac.ComputeHash(SeqInput(_inSeq, plain));
                    CollectionAssert.AreEqual(expected, mac, "inbound MAC mismatch");
                }

                _inSeq++;
                var paddingLength = plain[4];
                var dataLength = packetLength - paddingLength - 1;
                var payload = new byte[dataLength];
                Array.Copy(plain, 5, payload, 0, dataLength);
                return payload;
            }

            private static byte[] SeqInput(uint sequence, byte[] plain)
            {
                var input = new byte[4 + plain.Length];
                input[0] = (byte)(sequence >> 24);
                input[1] = (byte)(sequence >> 16);
                input[2] = (byte)(sequence >> 8);
                input[3] = (byte)sequence;
                plain.CopyTo(input, 4);
                return input;
            }

            private string ReadLine()
            {
                var builder = new StringBuilder();
                while (true)
                {
                    var value = _stream.ReadByte();
                    if (value < 0)
                        throw new EndOfStreamException();
                    if (value == '\n')
                        return builder.ToString();
                    if (value != '\r')
                        builder.Append((char)value);
                }
            }

            private byte[] ReadExactly(int length)
            {
                var buffer = new byte[length];
                var read = 0;
                while (read < length)
                {
                    var count = _stream.Read(buffer, read, length - read);
                    if (count == 0)
                        throw new EndOfStreamException();
                    read += count;
                }
                return buffer;
            }

            private void WriteBytes(byte[] data) => _stream.Write(data, 0, data.Length);

            public void Dispose()
            {
                _stream.Dispose();
                _outCipher?.Dispose();
                _inCipher?.Dispose();
                _outMac?.Dispose();
                _inMac?.Dispose();
            }
        }
    }
}
