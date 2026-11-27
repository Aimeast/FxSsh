using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Services;
using FxSsh.Tests.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Enforcement of the <see cref="SessionLimits"/> knobs that gate the
    /// connection service: the per-session channel cap and the bounded
    /// dispatch queue that disconnects a flooding peer.
    /// </summary>
    [TestClass]
    public sealed class SessionLimitsEnforcementTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;

        private ConnectionService CreateConnection(SessionLimits limits)
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _clientSocket.Connect(listener.LocalEndPoint!);
            _serverSocket = listener.Accept();

            _session = new Session(_serverSocket, new Dictionary<string, string>(), "SSH-2.0-FxSsh-Test", limits: limits);
            return new ConnectionService(_session, new UserAuthArgs(_session));
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _session?.Disconnect();
            _clientSocket?.Dispose();
            _serverSocket?.Dispose();
        }

        private static SessionOpenMessage OpenSessionMessage(uint senderChannel)
        {
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write("session", Encoding.ASCII)
                .Write(senderChannel)
                .Write(0x200000u)
                .Write(32768u)
                .ToByteArray());
            return Message.LoadFrom<SessionOpenMessage>(baseMessage);
        }

        private static ShellRequestMessage ShellRequest(uint recipientChannel)
        {
            var baseMessage = new ChannelRequestMessage();
            baseMessage.Load(TestMessages.Payload(ChannelRequestMessage.MessageNumber)
                .Write(recipientChannel)
                .Write("shell", Encoding.ASCII)
                .Write(false)
                .ToByteArray());
            return Message.LoadFrom<ShellRequestMessage>(baseMessage);
        }

        [TestMethod]
        public async Task Channel_open_over_MaximumChannels_is_refused()
        {
            var connection = CreateConnection(new SessionLimits { MaximumChannels = 1 });
            var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _session.Disconnected += (_, _) => disconnected.TrySetResult(true);

            // The first channel is accepted and stays functional. Requests
            // are addressed by the server channel id (first channel = 0).
            connection.HandleMessageCore(OpenSessionMessage(7));

            var firstOpened = new TaskCompletionSource<CommandRequestedArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.CommandOpened += (_, e) => firstOpened.TrySetResult(e);
            connection.HandleMessageCore(ShellRequest(0));
            var first = await firstOpened.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.AreEqual(7u, first.Channel.ClientChannelId);

            // The second channel open hits the cap and is refused, so a
            // request addressed to it never reaches any event handler.
            var secondOpened = new TaskCompletionSource<CommandRequestedArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.CommandOpened += (_, e) => secondOpened.TrySetResult(e);
            connection.HandleMessageCore(OpenSessionMessage(8));
            connection.HandleMessageCore(ShellRequest(1));

            try
            {
                await secondOpened.Task.WaitAsync(TimeSpan.FromMilliseconds(500));
                Assert.Fail("a channel over the MaximumChannels cap must be refused");
            }
            catch (TimeoutException)
            {
            }

            // The refusal is a channel-level rejection, not a session error.
            Assert.IsFalse(disconnected.Task.IsCompleted, "a refused open must not tear the session down");
        }

        [TestMethod]
        public async Task Channel_message_queue_overflow_disconnects_the_session()
        {
            var connection = CreateConnection(new SessionLimits { MaximumQueuedChannelMessages = 4 });
            var disconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _session.Disconnected += (_, _) => disconnected.TrySetResult(true);

            connection.HandleMessageCore(OpenSessionMessage(7));
            var opened = new TaskCompletionSource<CommandRequestedArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
            connection.CommandOpened += (_, e) => opened.TrySetResult(e);
            connection.HandleMessageCore(ShellRequest(0));
            var channel = (await opened.Task.WaitAsync(TimeSpan.FromSeconds(5))).Channel;

            // Block the single-reader dispatch loop inside the data handler,
            // so subsequently queued messages are not drained while the test
            // floods the bounded queue.
            var handlerEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var releaseHandler = new ManualResetEventSlim(false);
            channel.DataReceived += (_, _) =>
            {
                handlerEntered.TrySetResult(true);
                releaseHandler.Wait(TimeSpan.FromSeconds(10));
            };

            try
            {
                var data = new ChannelDataMessage { RecipientChannel = channel.ServerChannelId, Data = new byte[16] };
                connection.HandleMessageCore(data);
                await handlerEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

                // The queue holds 4 slots; the 5th queued message must trip
                // the overflow disconnect instead of growing memory.
                for (var i = 0; i < 12; i++)
                    connection.HandleMessageCore(data);

                await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            finally
            {
                releaseHandler.Set();
            }
        }
    }
}
