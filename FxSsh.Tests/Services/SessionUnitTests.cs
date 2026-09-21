using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Session behaviour that does not require a protocol handshake:
    /// construction guards, lifecycle guards, keepalive configuration and
    /// disconnect idempotency.
    /// </summary>
    [TestClass]
    public sealed class SessionUnitTests
    {
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

        [TestMethod]
        public void Constructor_validates_arguments()
        {
            var (client, server) = CreateSocketPair();
            var hostKey = new Dictionary<string, string>();

            Assert.ThrowsExactly<ArgumentNullException>(() => new Session(null!, hostKey, "SSH-2.0-X"));
            Assert.ThrowsExactly<ArgumentNullException>(() => new Session(server, null!, "SSH-2.0-X"));

            client.Dispose();
            server.Dispose();
        }

        [TestMethod]
        public async Task StartAsync_on_a_disconnected_socket_returns_immediately()
        {
            var (client, server) = CreateSocketPair();
            client.Dispose(); // "not connected" from the session's perspective

            var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-X");
            await session.StartAsync(); // must complete without error
            session.Disconnect();
            server.Dispose();
        }

        [TestMethod]
        public void Disconnect_fires_once_and_is_idempotent()
        {
            var (client, server) = CreateSocketPair();
            var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-X");
            var count = 0;
            session.Disconnected += (_, _) => count++;

            session.Disconnect(DisconnectReason.ByApplication, "bye");
            session.Disconnect(DisconnectReason.ProtocolError, "again");
            session.DisconnectAsync().Wait(TimeSpan.FromSeconds(5));

            Assert.AreEqual(1, count);
            client.Dispose();
            server.Dispose();
        }

        [TestMethod]
        public void Keepalive_and_extension_helpers_are_safe_before_start()
        {
            var (client, server) = CreateSocketPair();
            var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-X");

            session.ConfigureKeepalive(TimeSpan.FromSeconds(30));
            session.RegisterExtension("unit-test", "1");
            session.SendGlobalKeepalive();
            session.SendGlobalKeepalive();

            session.Disconnect();
            client.Dispose();
        }

        [TestMethod]
        public void ServerVersion_is_exposed()
        {
            var (client, server) = CreateSocketPair();
            var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-Unit");

            Assert.AreEqual("SSH-2.0-Unit", session.ServerVersion);

            session.Disconnect();
            client.Dispose();
        }

        [TestMethod]
        public async Task Keepalive_timeout_disconnects_an_unresponsive_client()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-Unit");
                var disconnected = new TaskCompletionSource<bool>();
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);

                // Probes fire every 150 ms; a raw client that only completes
                // the version exchange never answers them, so after three
                // missed probes the session must tear itself down.
                session.ConfigureKeepalive(TimeSpan.FromMilliseconds(150));
                _ = session.StartAsync();
                await client.SendAsync("SSH-2.0-Unit\r\n"u8.ToArray(), SocketFlags.None);

                await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }

        [TestMethod]
        public async Task Keepalive_probe_replies_reset_the_disconnect_counter()
        {
            var (client, server) = CreateSocketPair();
            try
            {
                var session = new Session(server, new Dictionary<string, string>(), "SSH-2.0-X");
                var disconnected = new TaskCompletionSource<bool>();
                session.Disconnected += (_, _) => disconnected.TrySetResult(true);

                session.ConfigureKeepalive(TimeSpan.FromMilliseconds(150));
                _ = session.StartAsync();
                await client.SendAsync("SSH-2.0-X\r\n"u8.ToArray(), SocketFlags.None);

                // A pre-NEWKEYS packet is plaintext: frame a valid
                // SSH_MSG_REQUEST_FAILURE (type 82) reply exactly like a real
                // peer would. Each reply proves liveness and resets the
                // missed-probe counter, so the session never disconnects.
                var probeReply = new byte[]
                {
                    0x00, 0x00, 0x00, 0x0C, // packet length = 12
                    0x0A,                   // padding length = 10
                    0x52,                   // SSH_MSG_REQUEST_FAILURE
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                };

                for (var i = 0; i < 12; i++)
                {
                    await Task.Delay(100);
                    await client.SendAsync(probeReply, SocketFlags.None);
                    Assert.IsFalse(disconnected.Task.IsCompleted, $"disconnect after {(i + 1) * 100} ms");
                }
            }
            finally
            {
                client.Dispose();
                server.Dispose();
            }
        }
    }
}
