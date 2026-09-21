using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Services;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Exercises Channel's flow-control state machine directly. A real
    /// Session is constructed over a loopback socket pair but never started:
    /// SendMessage queues into the session's send channel, so window
    /// accounting can be observed without any network traffic.
    /// </summary>
    [TestClass]
    public sealed class ChannelFlowControlTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;
        private ConnectionService _connection = null!;

        [TestInitialize]
        public void CreateSessionOverSocketPair()
        {
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

        [TestMethod]
        public void Constructor_applies_peer_and_local_defaults()
        {
            var channel = new SessionChannel(_connection, 42, 1111, 2222, 7);

            Assert.AreEqual(42u, channel.ClientChannelId);
            Assert.AreEqual(1111u, channel.ClientInitialWindowSize);
            Assert.AreEqual(1111u, channel.ClientWindowSize);
            Assert.AreEqual(2222u, channel.ClientMaxPacketSize);
            Assert.AreEqual(7u, channel.ServerChannelId);
            Assert.AreEqual(Session.InitialLocalWindowSize, (int)channel.ServerInitialWindowSize);
            Assert.AreEqual(Session.InitialLocalWindowSize, (int)channel.ServerWindowSize);
            Assert.AreEqual(Session.LocalChannelDataPacketSize, (int)channel.ServerMaxPacketSize);
            Assert.IsFalse(channel.PendingConfirmation);
            Assert.IsFalse(channel.ClientClosed);
            Assert.IsFalse(channel.ServerClosed);
        }

        [TestMethod]
        public void SendData_decrements_the_peer_window()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);

            channel.SendData(new byte[100]);
            Assert.AreEqual(900u, channel.ClientWindowSize);

            channel.SendData(new byte[100]);
            Assert.AreEqual(800u, channel.ClientWindowSize);
        }

        [TestMethod]
        public void SendData_exactly_consumes_the_window_then_blocks_until_adjusted()
        {
            var channel = new SessionChannel(_connection, 1, 100, 32768, 1000);

            channel.SendData(new byte[100]);
            Assert.AreEqual(0u, channel.ClientWindowSize);

            // The synchronous send path blocks while the peer window is
            // exhausted.
            var blocked = Task.Run(() => channel.SendData(new byte[10]));
            Assert.IsFalse(blocked.Wait(150), "SendData must block on an exhausted window");

            channel.ClientAdjustWindow(50);
            Assert.IsTrue(blocked.Wait(5000), "SendData must resume after a window adjust");
            Assert.AreEqual(40u, channel.ClientWindowSize);
        }

        [TestMethod]
        public async Task SendDataAsync_awaits_the_window_signal()
        {
            var channel = new SessionChannel(_connection, 1, 100, 32768, 1000);
            channel.SendData(new byte[100]);

            var pending = channel.SendDataAsync(new byte[10]);
            await Task.Delay(100);
            Assert.IsFalse(pending.IsCompleted, "SendDataAsync must wait for window credit");

            channel.ClientAdjustWindow(10);
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.AreEqual(0u, channel.ClientWindowSize);
        }

        [TestMethod]
        public async Task ForceClose_unblocks_pending_async_sends()
        {
            var channel = new SessionChannel(_connection, 1, 100, 32768, 1000);
            channel.SendData(new byte[100]);

            var pending = channel.SendDataAsync(new byte[10]);
            await Task.Delay(100);

            channel.ForceClose();

            await Assert.ThrowsExactlyAsync<ObjectDisposedException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5)));
        }

        [TestMethod]
        public void OnData_refreshes_the_local_window_at_half_threshold()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            var initial = channel.ServerInitialWindowSize;
            var chunk = new byte[Session.LocalChannelDataPacketSize];

            channel.OnData(chunk);
            Assert.AreEqual((uint)(Session.InitialLocalWindowSize - Session.LocalChannelDataPacketSize), channel.ServerWindowSize);

            // Feed packets until the half-window refresh tops the window back
            // up to its initial size (RFC 4254 5.2 "top up" semantics).
            var refreshed = false;
            for (var i = 0; i < 128 && !refreshed; i++)
            {
                channel.OnData(chunk);
                if (channel.ServerWindowSize == initial)
                    refreshed = true;
            }

            Assert.IsTrue(refreshed, "the local window was never refreshed");
        }

        [TestMethod]
        public void Eof_and_close_lifecycle_is_idempotent()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            var eofEvents = 0;
            var closeEvents = 0;
            channel.EofReceived += (_, _) => eofEvents++;
            channel.CloseReceived += (_, _) => closeEvents++;

            channel.SendEof();
            Assert.IsTrue(channel.ServerMarkedEof);
            Assert.IsFalse(channel.ServerClosed);

            channel.OnEof();
            Assert.IsTrue(channel.ClientMarkedEof);
            Assert.AreEqual(1, eofEvents);

            channel.SendClose();
            Assert.IsTrue(channel.ServerClosed);
            channel.SendClose(); // second close must not throw

            channel.OnClose();
            Assert.IsTrue(channel.ClientClosed);
            Assert.AreEqual(1, closeEvents);

            channel.ForceClose(); // double force-close must not throw
            channel.ForceClose();
        }

        [TestMethod]
        public void SendSignalClose_marks_closed_and_is_idempotent()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);

            channel.SendSignalClose("TERM");
            Assert.IsTrue(channel.ServerClosed);

            channel.SendSignalClose("KILL"); // second close must not throw
            channel.SendClose();             // no-op after signal close
        }

        [TestMethod]
        public void OnConfirmed_resolves_the_peer_and_flushes_pending_sends()
        {
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            Assert.IsTrue(pending.PendingConfirmation);
            Assert.AreEqual(0u, pending.ClientChannelId);

            pending.SendData(new byte[100]); // buffered while unconfirmed

            pending.OnConfirmed(7, peerInitialWindowSize: 500, peerMaximumPacketSize: 300);

            Assert.IsFalse(pending.PendingConfirmation);
            Assert.AreEqual(7u, pending.ClientChannelId);
            Assert.AreEqual(500u, pending.ClientInitialWindowSize);
            Assert.AreEqual(300u, pending.ClientMaxPacketSize);
            Assert.AreEqual(400u, pending.ClientWindowSize); // 500 credited - 100 flushed

            pending.OnConfirmed(8, 100, 100); // second confirm is a no-op
            Assert.AreEqual(7u, pending.ClientChannelId);
        }

        [TestMethod]
        public async Task Pending_async_send_flushes_on_confirmation()
        {
            // Mirrors PortForwardingService's bridge: SendDataAsync while the
            // channel is pending returns immediately (bytes are queued), and
            // OnConfirmed flushes them with correct window accounting.
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            var sendTask = pending.SendDataAsync(new byte[100]);
            await sendTask.WaitAsync(TimeSpan.FromSeconds(5)); // completes by queueing

            pending.OnConfirmed(7, peerInitialWindowSize: 500, peerMaximumPacketSize: 300);

            Assert.AreEqual(400u, pending.ClientWindowSize); // 500 credited - 100 flushed
        }

        [TestMethod]
        public async Task SendDataAsync_racing_confirmation_still_sends()
        {
            // The pump may call SendDataAsync concurrently with the session
            // thread processing OPEN_CONFIRMATION: both orderings must make
            // progress (never park on an unresolved zero window).
            for (var i = 0; i < 200; i++)
            {
                var pending = new PendingChannel(_connection, serverChannelId: 9);
                var sendTask = pending.SendDataAsync(new byte[44]);
                pending.OnConfirmed(1, peerInitialWindowSize: 2097152, peerMaximumPacketSize: 32768);
                await sendTask.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }

        private sealed class PendingChannel : Channel
        {
            public PendingChannel(ConnectionService connectionService, uint serverChannelId)
                : base(connectionService, serverChannelId)
            {
            }
        }
    }
}
