using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Transport state-machine tests that need a raw (pre-key-exchange)
    /// packet stream: strict KEX advertisement/enforcement and the NEWKEYS
    /// ordering guard. Everything here happens before encryption starts, so
    /// the client side is plain SSH packet framing.
    /// </summary>
    [TestClass]
    public sealed class SessionKexStateTests
    {
        private const string ClientBanner = "SSH-2.0-UnitClient";

        private static (Socket Client, Socket Server) CreateSocketPair()
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(listener.LocalEndPoint!);
            var server = listener.Accept();
            return (client, server);
        }

        private static Session CreateSession(Socket server)
        {
            var hostKeys = new Dictionary<string, string>
            {
                ["ecdsa-sha2-nistp256"] = KeyGenerator.GenerateECDsaKeyPem("nistp256"),
            };
            return new Session(server, hostKeys, "SSH-2.0-Unit");
        }

        private static byte[] ClientKexInit(bool strict)
        {
            var kex = strict
                ? new[] { "diffie-hellman-group14-sha256", "kex-strict-c-v00@openssh.com" }
                : new[] { "diffie-hellman-group14-sha256" };

            return new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = kex,
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

        private static void WritePacket(Stream stream, ReadOnlySpan<byte> payload)
        {
            // RFC 4253 section 6: padding makes the whole packet (length +
            // padding_length + payload + padding) a multiple of 8 pre-KEX.
            var padding = 8 - (payload.Length + 5) % 8;
            if (padding < 4)
                padding += 8;

            var packetLength = payload.Length + padding + 1;
            Span<byte> header = stackalloc byte[5];
            header[0] = (byte)(packetLength >> 24);
            header[1] = (byte)(packetLength >> 16);
            header[2] = (byte)(packetLength >> 8);
            header[3] = (byte)packetLength;
            header[4] = (byte)padding;

            stream.Write(header);
            stream.Write(payload);

            Span<byte> pad = stackalloc byte[padding];
            stream.Write(pad);
        }

        private static void ReadExactly(Stream stream, Span<byte> buffer)
        {
            var read = 0;
            while (read < buffer.Length)
            {
                var count = stream.Read(buffer[read..]);
                if (count == 0)
                    throw new EndOfStreamException();
                read += count;
            }
        }

        private static string ReadLine(Stream stream)
        {
            var builder = new StringBuilder();
            while (true)
            {
                var value = stream.ReadByte();
                if (value < 0)
                    throw new EndOfStreamException();
                if (value == '\n')
                    return builder.ToString();
                if (value != '\r')
                    builder.Append((char)value);
            }
        }

        private static byte[] ReadPacket(Stream stream)
        {
            Span<byte> lengthBytes = stackalloc byte[4];
            ReadExactly(stream, lengthBytes);
            var packetLength = lengthBytes[0] << 24 | lengthBytes[1] << 16 | lengthBytes[2] << 8 | lengthBytes[3];

            var body = new byte[packetLength];
            ReadExactly(stream, body);

            var padding = body[0];
            return body.AsSpan(1, packetLength - padding - 1).ToArray();
        }

        private static void SendClientBanner(Stream stream)
            => stream.Write(Encoding.ASCII.GetBytes(ClientBanner + "\r\n"));

        [TestMethod]
        public async Task Initial_kexinit_advertises_the_strict_kex_marker()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = CreateSession(server);
                _ = session.StartAsync();

                using var stream = new NetworkStream(client, ownsSocket: false) { ReadTimeout = 5000 };
                Assert.AreEqual("SSH-2.0-Unit", ReadLine(stream));
                SendClientBanner(stream);

                var kexInit = new KeyExchangeInitMessage();
                kexInit.Load(ReadPacket(stream));

                CollectionAssert.Contains(kexInit.KeyExchangeAlgorithms, "kex-strict-s-v00@openssh.com");
                session.Disconnect();
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [TestMethod]
        public async Task Strict_kex_rejects_unexpected_packets_during_the_initial_exchange()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = CreateSession(server);
                var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);
                _ = session.StartAsync();

                using var stream = new NetworkStream(client, ownsSocket: false);
                SendClientBanner(stream);
                WritePacket(stream, ClientKexInit(strict: true));
                // SSH_MSG_IGNORE (2) with an empty payload string. Without
                // strict KEX the server would silently ignore it and stay up.
                WritePacket(stream, new byte[] { 2, 0, 0, 0, 0 });

                await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [TestMethod]
        public async Task Non_strict_clients_keep_the_legacy_tolerance_for_ignore_packets()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = CreateSession(server);
                var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);
                _ = session.StartAsync();

                using var stream = new NetworkStream(client, ownsSocket: false);
                SendClientBanner(stream);
                WritePacket(stream, ClientKexInit(strict: false));
                WritePacket(stream, new byte[] { 2, 0, 0, 0, 0 });

                await Task.Delay(300);
                Assert.IsFalse(disconnected.Task.IsCompleted,
                    "SSH_MSG_IGNORE must remain legal when strict KEX was not negotiated");

                session.Disconnect();
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [TestMethod]
        public async Task Newkeys_without_a_completed_key_exchange_disconnects()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = CreateSession(server);
                var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);
                _ = session.StartAsync();

                using var stream = new NetworkStream(client, ownsSocket: false);
                SendClientBanner(stream);
                WritePacket(stream, ClientKexInit(strict: false));
                // Skip KEXDH_INIT entirely and claim the keys are ready.
                WritePacket(stream, new NewKeysMessage().GetPacket());

                await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [TestMethod]
        public async Task First_kex_packet_is_discarded_when_the_client_first_choice_is_not_the_server_first_choice()
        {
            // RFC 4253 7.1: a guess is right only when both sides prefer the
            // same kex and host key algorithm. Here the server supports the
            // client's first kex but ranks another one higher, so the client
            // (e.g. dropbear 2018.76) guessed wrong and resends KEXDH_INIT.
            // The server must ignore the guessed packet and reply only once.
            const string ClientKex = "curve25519-sha256";
            var (client, server) = CreateSocketPair();
            try
            {
                var session = CreateSession(server);
                var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);
                _ = session.StartAsync();

                using var stream = new NetworkStream(client, ownsSocket: false) { ReadTimeout = 5000 };
                Assert.AreEqual("SSH-2.0-Unit", ReadLine(stream));
                SendClientBanner(stream);

                var serverKexInit = new KeyExchangeInitMessage();
                serverKexInit.Load(ReadPacket(stream));
                CollectionAssert.Contains(serverKexInit.KeyExchangeAlgorithms, ClientKex);
                Assert.AreNotEqual(ClientKex, serverKexInit.KeyExchangeAlgorithms[0],
                    "test needs a server that prefers a different kex than the client");

                WritePacket(stream, new KeyExchangeInitMessage
                {
                    KeyExchangeAlgorithms = [ClientKex],
                    ServerHostKeyAlgorithms = ["ecdsa-sha2-nistp256"],
                    EncryptionAlgorithmsClientToServer = ["aes256-ctr"],
                    EncryptionAlgorithmsServerToClient = ["aes256-ctr"],
                    MacAlgorithmsClientToServer = ["hmac-sha2-256"],
                    MacAlgorithmsServerToClient = ["hmac-sha2-256"],
                    CompressionAlgorithmsClientToServer = ["none"],
                    CompressionAlgorithmsServerToClient = ["none"],
                    LanguagesClientToServer = [""],
                    LanguagesServerToClient = [""],
                    FirstKexPacketFollows = true,
                }.GetPacket());

                // The guessed KEXDH_INIT carries a malformed 5-byte Q_C, so
                // processing it instead of discarding it would fail the exchange.
                WritePacket(stream, new byte[] { 30, 0, 0, 0, 1, 0 });

                var publicKey = new byte[32];
                Random.Shared.NextBytes(publicKey);
                var init = new byte[1 + 4 + publicKey.Length];
                init[0] = 30;
                init[4] = (byte)publicKey.Length;
                publicKey.CopyTo(init, 5);
                WritePacket(stream, init);

                var replies = 0;
                stream.ReadTimeout = 1000;
                try
                {
                    while (true)
                    {
                        var payload = ReadPacket(stream);
                        if (payload[0] == 31)
                            replies++;
                    }
                }
                catch (IOException)
                {
                    // Read timeout: the server has nothing more to send.
                }

                Assert.AreEqual(1, replies, "server must answer only the resent KEXDH_INIT");
                Assert.IsFalse(disconnected.Task.IsCompleted);
                session.Disconnect();
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }
    }
}
