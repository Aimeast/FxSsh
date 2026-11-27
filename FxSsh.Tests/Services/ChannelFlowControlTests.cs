using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Messages.Connection;
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
        public void Constructor_rejects_a_zero_peer_packet_size()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new SessionChannel(_connection, 1, 1000, 0, 1000));
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
        public void ForceClose_isolates_a_throwing_handler_and_still_unregisters_the_channel()
        {
            // Regression: a ForceClosed subscriber that throws used to skip
            // both the remaining subscribers and RemoveChannel, so bridges
            // kept their external sockets and the closed channel stayed
            // registered for the rest of the session.
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            var laterHandlers = 0;
            channel.ForceClosed += (_, _) => throw new InvalidOperationException("host handler failure");
            channel.ForceClosed += (_, _) => laterHandlers++;

            var channels = (Dictionary<uint, Channel>)typeof(ConnectionService)
                .GetField("_channels", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(_connection)!;
            channels[channel.ServerChannelId] = channel;

            channel.ForceClose(); // must not surface the subscriber failure

            Assert.AreEqual(1, laterHandlers, "a throwing subscriber must not skip the remaining subscribers");
            Assert.IsFalse(channels.ContainsKey(channel.ServerChannelId),
                "the closed channel must still be unregistered from the connection service");
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
        public async Task SendCloseAsync_waits_for_the_in_flight_send_before_closing()
        {
            var channel = new SessionChannel(_connection, 1, 100, 32768, 1000);
            channel.SendData(new byte[100]); // exhausts the peer window

            var pending = channel.SendDataAsync(new byte[10]);
            await Task.Delay(100);
            Assert.IsFalse(pending.IsCompleted, "the send must park on the exhausted window");

            var close = channel.SendCloseAsync();
            await Task.Delay(100);
            Assert.IsFalse(close.IsCompleted,
                "CLOSE must queue behind the send that already owns the send gate");

            channel.ClientAdjustWindow(10);
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
            await close.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.IsTrue(channel.ServerClosed);
        }

        [TestMethod]
        public void Backlog_over_the_cap_is_rejected_before_confirmation()
        {
            // A channel still awaiting OPEN_CONFIRMATION copies every send
            // into its backlog; the per-channel cap bounds that queue.
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            var chunk = new byte[1024 * 1024];
            var attempts = pending.MaximumBufferedSendBytes / chunk.Length;

            for (var i = 0; i < attempts; i++)
                pending.SendData(chunk); // completes by queueing

            Assert.ThrowsExactly<InvalidOperationException>(() => pending.SendData(chunk));

            pending.ForceClose();
        }

        [TestMethod]
        public async Task SendDataAsync_larger_than_the_cap_streams_when_the_window_allows()
        {
            // A direct send streams chunk-by-chunk from the caller's buffer,
            // so a payload larger than the per-channel cap is not rejected up
            // front; it only parks when the peer window is exhausted.
            var channel = new SessionChannel(_connection, 1, 0, 32768, 1000);
            var pending = channel.SendDataAsync(new byte[channel.MaximumBufferedSendBytes + 1]);
            await Task.Delay(100);
            Assert.IsFalse(pending.IsCompleted, "the oversized call must park on the zero window, not fail");

            channel.ClientAdjustWindow((uint)channel.MaximumBufferedSendBytes + 1);
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
        }

        [TestMethod]
        public void Close_and_eof_after_force_close_are_no_ops()
        {
            var channel = new SessionChannel(_connection, 1, 1000, 32768, 1000);
            channel.ForceClose();

            channel.SendClose();
            channel.SendEof();
            channel.SendSignalClose("TERM");

            Assert.IsFalse(channel.ServerClosed);
            Assert.IsFalse(channel.ServerMarkedEof);
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
        public void Eof_and_close_requested_before_confirmation_are_deferred()
        {
            var pendingEof = new PendingChannel(_connection, serverChannelId: 9);
            pendingEof.SendData(new byte[10]);
            pendingEof.SendEof();
            Assert.IsFalse(pendingEof.ServerMarkedEof,
                "EOF must not overtake data buffered before OPEN_CONFIRMATION");

            pendingEof.OnConfirmed(7, peerInitialWindowSize: 500, peerMaximumPacketSize: 300);
            Assert.IsTrue(pendingEof.ServerMarkedEof);

            var pendingClose = new PendingChannel(_connection, serverChannelId: 11);
            pendingClose.SendData(new byte[10]);
            pendingClose.SendClose(3);
            Assert.IsFalse(pendingClose.ServerClosed,
                "CLOSE must not overtake data buffered before OPEN_CONFIRMATION");

            pendingClose.OnConfirmed(8, peerInitialWindowSize: 500, peerMaximumPacketSize: 300);
            Assert.IsTrue(pendingClose.ServerClosed);
            Assert.AreEqual(490u, pendingClose.ClientWindowSize);
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

        [TestMethod]
        public void Deferred_close_goes_out_after_the_remainder_missed_by_the_initial_flush()
        {
            // The producer queued more than the peer's initial window before
            // OPEN_CONFIRMATION, and a close was requested while pending: the
            // flush only sends what fits, so the CLOSE must stay deferred
            // until WINDOW_ADJUST releases the remainder - otherwise the
            // queued CHANNEL_DATA would follow the CLOSE on the wire.
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            pending.SendData(new byte[100]);
            pending.SendClose();

            pending.OnConfirmed(7, peerInitialWindowSize: 60, peerMaximumPacketSize: 300);
            Assert.IsFalse(pending.ServerClosed,
                "CLOSE must stay deferred while queued data missed the initial window");
            CollectionAssert.AreEqual(
                new[] { ChannelDataMessage.MessageNumber },
                DrainSentMessageTypes(_session),
                "only the part fitting the initial window may be sent before the adjust");

            pending.ClientAdjustWindow(40);
            Assert.IsTrue(pending.ServerClosed);
            Assert.AreEqual(0u, pending.ClientWindowSize);
            CollectionAssert.AreEqual(
                new[] { ChannelDataMessage.MessageNumber, ChannelCloseMessage.MessageNumber },
                DrainSentMessageTypes(_session),
                "the CLOSE must follow the last queued data byte on the wire");
        }

        [TestMethod]
        public async Task SendCloseAsync_after_confirmation_waits_for_the_window_blocked_remainder()
        {
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            pending.SendData(new byte[100]);
            pending.OnConfirmed(7, peerInitialWindowSize: 60, peerMaximumPacketSize: 300);
            Assert.AreEqual(0u, pending.ClientWindowSize); // 40 bytes still queued

            var close = pending.SendCloseAsync();
            await Task.Delay(100);
            // SendCloseAsync completes as soon as the request is recorded
            // (same as the pre-confirmation deferral); the meaningful check
            // is that the CLOSE frame itself stays unsent.
            Assert.IsFalse(pending.ServerClosed, "CLOSE must wait for the queued remainder to drain");

            pending.ClientAdjustWindow(40);
            await close.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsTrue(pending.ServerClosed);

            CollectionAssert.AreEqual(
                new[] { ChannelDataMessage.MessageNumber, ChannelDataMessage.MessageNumber, ChannelCloseMessage.MessageNumber },
                DrainSentMessageTypes(_session),
                "every queued data byte must precede the CLOSE");
        }

        [TestMethod]
        public void Deferred_eof_goes_out_after_the_remainder_missed_by_the_initial_flush()
        {
            var pending = new PendingChannel(_connection, serverChannelId: 9);
            pending.SendData(new byte[100]);
            pending.SendEof();

            pending.OnConfirmed(7, peerInitialWindowSize: 60, peerMaximumPacketSize: 300);
            Assert.IsFalse(pending.ServerMarkedEof, "EOF must wait for the queued remainder");

            pending.ClientAdjustWindow(40);
            Assert.IsTrue(pending.ServerMarkedEof);
            Assert.AreEqual(0u, pending.ClientWindowSize);
        }

        /// <summary>
        /// Drain the session's outbound queue (the session is never started,
        /// so frames stay plaintext) and return the SSH message number of
        /// each queued frame in order - payload byte 0, at wire offset 5 of
        /// the [length(4)][padding_length(1)][payload] frame.
        /// </summary>
        private static List<byte> DrainSentMessageTypes(Session session)
        {
            var channel = session.GetType()
                .GetField("_sendChannel", BindingFlags.NonPublic | BindingFlags.Instance)!
                .GetValue(session)!;
            var reader = channel.GetType().GetProperty("Reader")!.GetValue(channel)!;
            var tryRead = reader.GetType().GetMethod("TryRead")!;

            var messageNumbers = new List<byte>();
            var arguments = new object?[1];
            while ((bool)tryRead.Invoke(reader, arguments)! && arguments[0] != null)
            {
                var buffer = arguments[0]!;
                var bufferType = buffer.GetType();
                var array = (byte[])bufferType
                    .GetProperty("Array", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!
                    .GetValue(buffer)!;
                var length = (int)bufferType
                    .GetProperty("Length", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!
                    .GetValue(buffer)!;

                Assert.IsTrue(length >= 6, "a queued frame must carry at least one payload byte");
                messageNumbers.Add(array[5]);

                bufferType.GetMethod("Dispose", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)!
                    .Invoke(buffer, null);
            }

            return messageNumbers;
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
