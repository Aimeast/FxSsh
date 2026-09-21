using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Logging;
using FxSsh.Services;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Exercises the reverse-forwarding TCP listener end to end over a real
    /// loopback socket: accept, forwarded-channel bridge in both directions,
    /// teardown events and listener disposal.
    /// </summary>
    [TestClass]
    public sealed class PortForwardingServiceTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;
        private ConnectionService _connection = null!;

        [TestInitialize]
        public void CreateSessionOverSocketPair()
        {
            Log.Configure(new LogOptions { MinLevel = LogLevel.Trace, Sink = new ConsoleLogSink() });

            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _clientSocket.Connect(listener.LocalEndPoint!);
            _serverSocket = listener.Accept();

            _session = new Session(_serverSocket, new Dictionary<string, string>(), "SSH-2.0-FxSsh-Test");
            _connection = new ConnectionService(_session, new UserAuthArgs(_session));
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _clientSocket.Dispose();
            _serverSocket.Dispose();
        }

        private sealed class PendingChannel : Channel
        {
            public PendingChannel(ConnectionService connectionService, uint serverChannelId)
                : base(connectionService, serverChannelId)
            {
            }
        }

        private static int GetFreePort()
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        /// <summary>
        /// Probed free ports occasionally collide with parallel tests; retry
        /// the bind on SocketException.
        /// </summary>
        private static PortForwardingService StartOnFreePort(Func<string, uint, string, uint, Channel> factory, out int port)
        {
            for (var attempt = 0; ; attempt++)
            {
                var candidate = GetFreePort();
                var service = new PortForwardingService("127.0.0.1", (uint)candidate, factory);
                try
                {
                    service.Start();
                    port = candidate;
                    return service;
                }
                catch (SocketException) when (attempt < 10)
                {
                    Thread.Sleep(50);
                }
            }
        }

        private static async Task<Socket> ConnectAsync(int port)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(5));
            return socket;
        }

        [TestMethod]
        public async Task Bridge_relays_channel_data_to_the_tcp_client()
        {
            var factoryCalled = new TaskCompletionSource<bool>();
            Channel? forwarded = null;

            var service = StartOnFreePort((addr, port, oip, oport) =>
            {
                var channel = new PendingChannel(_connection, 0);
                forwarded = channel;
                factoryCalled.TrySetResult((addr, port, oip, oport) != default);
                return channel;
            }, out var freePort);
            Assert.AreEqual("127.0.0.1", service.BoundAddress);
            Assert.AreEqual(freePort, (int)service.BoundPort);

            using var client = await ConnectAsync(freePort);
            await factoryCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // BridgeAsync hooks the channel right after the factory returns;
            // give the accept loop a moment to finish that wiring.
            await Task.Delay(300);

            forwarded!.OnConfirmed(1, peerInitialWindowSize: 2097152, peerMaximumPacketSize: 32768);

            // Channel -> TCP: data the peer sends into the forwarded channel
            // must reach the local TCP client. (Driven via OnData - the
            // internal entry point ConnectionService calls.)
            var reply = Encoding.ASCII.GetBytes("pf-pong");
            forwarded.OnData(reply);
            var buffer = new byte[reply.Length];
            var total = 0;
            while (total < buffer.Length)
            {
                var read = await client.ReceiveAsync(buffer.AsMemory(total), SocketFlags.None)
                    .AsTask().WaitAsync(TimeSpan.FromSeconds(5));
                if (read == 0)
                    break;
                total += read;
            }

            CollectionAssert.AreEqual(reply, buffer[..total]);
            service.Dispose();
        }

        [TestMethod]
        public async Task Tcp_client_bytes_are_forwarded_into_the_channel()
        {
            var factoryCalled = new TaskCompletionSource<bool>();
            Channel? forwarded = null;

            var service = StartOnFreePort((_, _, _, _) =>
            {
                forwarded = new PendingChannel(_connection, 0);
                factoryCalled.TrySetResult(true);
                return forwarded;
            }, out var freePort);

            using var client = await ConnectAsync(freePort);
            await factoryCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            forwarded!.OnConfirmed(1, 2097152, 32768);

            // TCP -> channel pump: bytes must reach SendDataAsync without
            // blocking or erroring (the session send queue absorbs them).
            await client.SendAsync(Encoding.ASCII.GetBytes("pf-ping"), SocketFlags.None);
            await Task.Delay(300);

            Assert.IsFalse(forwarded.ServerMarkedEof);
            service.Dispose();
        }

        [TestMethod]
        public async Task Client_disconnect_closes_the_bridge_and_raises_events()
        {
            var factoryCalled = new TaskCompletionSource<bool>();
            Channel? forwarded = null;

            var service = StartOnFreePort((_, _, _, _) =>
            {
                forwarded = new PendingChannel(_connection, 0);
                factoryCalled.TrySetResult(true);
                return forwarded;
            }, out var freePort);

            using var client = await ConnectAsync(freePort);
            await factoryCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            forwarded!.OnConfirmed(1, 2097152, 32768);

            var closed = new TaskCompletionSource<Channel>();
            service.ForwardedChannelClosed += (_, ch) => closed.TrySetResult(ch);

            client.Shutdown(SocketShutdown.Both);
            client.Close();
            var closedChannel = await closed.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.AreSame(forwarded, closedChannel);
            Assert.IsTrue(forwarded.ServerMarkedEof, "bridge must send EOF on the channel");
            service.Dispose();
        }

        [TestMethod]
        public async Task Null_factory_drops_the_tcp_connection()
        {
            var factoryCalled = new TaskCompletionSource<bool>();
            var service = StartOnFreePort((_, _, _, _) =>
            {
                factoryCalled.TrySetResult(true);
                return null;
            }, out var port);

            using var client = await ConnectAsync(port);
            await factoryCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // The service closes the socket right after dropping the channel.
            var buffer = new byte[16];
            var read = await client.ReceiveAsync(buffer, SocketFlags.None).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.AreEqual(0, read);
            service.Dispose();
        }

        [TestMethod]
        public void Port_zero_binds_an_os_assigned_port()
        {
            using var service = new PortForwardingService("127.0.0.1", 0, (_, _, _, _) => null);
            service.Start();

            Assert.IsTrue(service.BoundPort > 0);
            service.Dispose();
        }

        [TestMethod]
        public async Task Dispose_stops_the_listener()
        {
            var service = StartOnFreePort((_, _, _, _) => null, out var port);

            service.Dispose();
            service.Dispose(); // idempotent

            await Assert.ThrowsExactlyAsync<SocketException>(
                async () => await ConnectAsync(port).WaitAsync(TimeSpan.FromSeconds(3)));
        }

        [TestMethod]
        public void Constructor_rejects_out_of_range_port()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new PortForwardingService("127.0.0.1", (uint)ushort.MaxValue + 1, (_, _, _, _) => null));
        }
    }
}
