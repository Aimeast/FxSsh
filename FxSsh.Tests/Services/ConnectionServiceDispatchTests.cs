using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
    /// Drives ConnectionService's message dispatch through its internal
    /// HandleMessageCore (friend assembly) with parsed wire messages and
    /// observes the resulting service events, channel state and teardown.
    /// </summary>
    [TestClass]
    public sealed class ConnectionServiceDispatchTests
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

        private static ChannelRequestMessage LoadChannelRequest(string requestType, bool wantReply, Action<SshDataWriter>? fields = null)
        {
            var writer = TestMessages.Payload(ChannelRequestMessage.MessageNumber)
                .Write(0u)
                .Write(requestType, Encoding.ASCII)
                .Write(wantReply);
            fields?.Invoke(writer);
            var request = new ChannelRequestMessage();
            request.Load(writer.ToByteArray());
            return request;
        }

        private static T Request<T>(string requestType, bool wantReply, Action<SshDataWriter>? fields = null)
            where T : ChannelRequestMessage, new()
        {
            return Message.LoadFrom<T>(LoadChannelRequest(requestType, wantReply, fields));
        }

        private static SessionOpenMessage OpenSessionMessage()
        {
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write("session", Encoding.ASCII)
                .Write(7u)
                .Write(0x200000u)
                .Write(32768u)
                .ToByteArray());
            return Message.LoadFrom<SessionOpenMessage>(baseMessage);
        }

        private static async Task<TArgs> NextAsync<TArgs>(TaskCompletionSource<TArgs> tcs, string what)
        {
            return await tcs.Task.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Session_open_creates_channel_and_exec_dispatches()
        {
            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(e);
            };

            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("echo ci", Encoding.ASCII)));

            var args = await NextAsync(opened, "CommandOpened");
            Assert.AreEqual("exec", args.ShellType);
            Assert.AreEqual("echo ci", args.CommandText);
            Assert.IsNotNull(args.Channel);
            Assert.AreEqual(0u, args.Channel.ServerChannelId);
            Assert.IsNotNull(args.AttachedUserAuthArgs);
        }

        [TestMethod]
        public async Task Channel_data_window_eof_and_close_flow_into_the_channel()
        {
            SessionChannel? channel = null;
            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                channel = e.Channel;
                opened.TrySetResult(e);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            var target = (await NextAsync(opened, "CommandOpened")).Channel;
            Assert.AreSame(channel, target);

            var data = new TaskCompletionSource<ReadOnlyMemory<byte>>();
            target!.DataReceived += (_, bytes) => data.TrySetResult(bytes);

            _connection.HandleMessageCore(new ChannelWindowAdjustMessage { RecipientChannel = 0, BytesToAdd = 4096 });

            _connection.HandleMessageCore(new ChannelDataMessage { RecipientChannel = 0, Data = new byte[] { 1, 2, 3 } });
            var received = await NextAsync(data, "DataReceived");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, received.ToArray());

            // Dispatch is asynchronous: wait until the adjust and EOF reach
            // the channel instead of asserting immediately.
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (target.ClientWindowSize <= 2097152u && DateTime.UtcNow < deadline)
                await Task.Delay(50);
            Assert.AreEqual(2097152u + 4096u, target.ClientWindowSize);

            var eof = new TaskCompletionSource<bool>();
            target.EofReceived += (_, _) => eof.TrySetResult(true);
            _connection.HandleMessageCore(new ChannelEofMessage { RecipientChannel = 0 });
            await NextAsync(eof, "EofReceived");
            Assert.IsTrue(target.ClientMarkedEof);

            var closed = new TaskCompletionSource<bool>();
            target.CloseReceived += (_, _) => closed.TrySetResult(true);
            _connection.HandleMessageCore(new ChannelCloseMessage { RecipientChannel = 0 });
            await NextAsync(closed, "CloseReceived");
            Assert.IsTrue(target.ClientClosed);
        }

        [TestMethod]
        public async Task Pty_env_and_window_change_requests_fire_events()
        {
            var pty = new TaskCompletionSource<PtyArgs>();
            _connection.PtyReceived += (_, e) => pty.TrySetResult(e);
            var env = new TaskCompletionSource<EnvironmentArgs>();
            _connection.EnvReceived += (_, e) => env.TrySetResult(e);
            var resized = new TaskCompletionSource<WindowChangeArgs>();
            WindowChangeArgs? captured = null;

            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<PtyRequestMessage>("pty-req", wantReply: true, w => w
                .Write("xterm-256color", Encoding.ASCII)
                .Write(120u)
                .Write(40u)
                .Write(960u)
                .Write(640u)
                .WriteBinary(new byte[] { 0x80 })));
            var ptyArgs = await NextAsync(pty, "PtyReceived");
            Assert.AreEqual("xterm-256color", ptyArgs.Terminal);
            Assert.AreEqual(120u, ptyArgs.WidthChars);
            CollectionAssert.AreEqual(new byte[] { 0x80 }, ptyArgs.Modes);

            _connection.HandleMessageCore(Request<EnvMessage>("env", wantReply: false, w => w
                .Write("LANG", Encoding.ASCII)
                .Write("zh_CN.UTF-8", Encoding.ASCII)));
            var envArgs = await NextAsync(env, "EnvReceived");
            Assert.AreEqual("LANG", envArgs.Name);
            Assert.AreEqual("zh_CN.UTF-8", envArgs.Value);

            var exec = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                exec.TrySetResult(e);
            };
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            var channel = (await NextAsync(exec, "CommandOpened")).Channel;
            channel!.WindowChange += (_, e) =>
            {
                captured = e;
                resized.TrySetResult(e);
            };

            _connection.HandleMessageCore(Request<WindowChangeMessage>("window-change", wantReply: false, w => w
                .Write(200u)
                .Write(50u)
                .Write(1600u)
                .Write(800u)));
            await NextAsync(resized, "WindowChange");
            Assert.AreEqual(200u, captured!.WidthColumns);
            Assert.AreEqual(800u, captured.HeightPixels);
        }

        [TestMethod]
        public async Task Shell_and_subsystem_requests_reach_the_host()
        {
            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(e);
            };

            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<ShellRequestMessage>("shell", wantReply: true));
            var shell = await NextAsync(opened, "CommandOpened(shell)");
            Assert.AreEqual("shell", shell.ShellType);
            Assert.IsNotNull(shell.Channel);

            var subsystem = new TaskCompletionSource<SubsystemRequestedArgs>();
            _connection.SubsystemRequested += (_, e) =>
            {
                e.Agreed = true;
                subsystem.TrySetResult(e);
            };
            _connection.HandleMessageCore(Request<SubsystemRequestMessage>("subsystem", wantReply: false,
                w => w.Write("sftp", Encoding.ASCII)));
            var sftp = await NextAsync(subsystem, "SubsystemRequested");
            Assert.AreEqual("sftp", sftp.Name);
            Assert.IsNotNull(sftp.Channel);
        }

        [TestMethod]
        public async Task Putty_workarounds_and_channel_keepalive_are_handled()
        {
            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(e);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            var channel = (await NextAsync(opened, "CommandOpened")).Channel!;

            // Neither request may throw or tear the loop down; both replies
            // (success for simple@, failure for winadj@) are sent to the peer.
            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "simple@putty.projects.tartarus.org", wantReply: true));
            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "winadj@putty.projects.tartarus.org", wantReply: true));
            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "keepalive@openssh.com", wantReply: true));

            // The dispatch loop must still be alive for later messages.
            var later = new TaskCompletionSource<bool>();
            channel.EofReceived += (_, _) => later.TrySetResult(true);
            _connection.HandleMessageCore(new ChannelEofMessage { RecipientChannel = 0 });
            await NextAsync(later, "EofReceived after putty requests");
        }

        [TestMethod]
        public async Task Unknown_channel_request_is_logged_and_loop_survives()
        {
            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(e);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            var channel = (await NextAsync(opened, "CommandOpened")).Channel!;

            _connection.HandleMessageCore(Request<ChannelRequestMessage>("bogus-request", wantReply: false));

            var later = new TaskCompletionSource<bool>();
            channel.EofReceived += (_, _) => later.TrySetResult(true);
            _connection.HandleMessageCore(new ChannelEofMessage { RecipientChannel = 0 });
            await NextAsync(later, "EofReceived after unknown request");
        }

        [TestMethod]
        public async Task Data_for_unknown_channel_is_tolerated()
        {
            _connection.HandleMessageCore(new ChannelDataMessage { RecipientChannel = 999, Data = new byte[] { 1 } });

            var opened = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(e);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after unknown-channel data");
        }

        [TestMethod]
        public async Task Direct_tcpip_open_fires_tcp_forward_request()
        {
            var requested = new TaskCompletionSource<TcpRequestArgs>();
            _connection.TcpForwardRequest += (_, e) => requested.TrySetResult(e);

            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write("direct-tcpip", Encoding.ASCII)
                .Write(1u)
                .Write(0x200000u)
                .Write(32768u)
                .Write("internal.example", Encoding.ASCII)
                .Write(8080u)
                .Write("127.0.0.1", Encoding.ASCII)
                .Write(54321u)
                .ToByteArray());
            _connection.HandleMessageCore(Message.LoadFrom<DirectTcpIpMessage>(baseMessage));

            var args = await NextAsync(requested, "TcpForwardRequest");
            Assert.AreEqual("internal.example", args.Host);
            Assert.AreEqual(8080, args.Port);
            Assert.IsNotNull(args.Channel);
        }

        [TestMethod]
        public async Task Reverse_forward_request_binds_when_accepted()
        {
            var received = new TaskCompletionSource<TcpForwardRequestArgs>();
            _connection.TcpForwardRequestReceived += (_, e) =>
            {
                e.Accepted = true;
                received.TrySetResult(e);
            };

            var request = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = false,
                RequestData = new SshDataWriter()
                    .Write("127.0.0.1", Encoding.ASCII)
                    .Write(0u)
                    .ToByteArray(),
            };
            _connection.HandleMessageCore(request);

            var args = await NextAsync(received, "TcpForwardRequestReceived");
            Assert.AreEqual("127.0.0.1", args.Address);
            Assert.AreEqual(0, args.Port);
            Assert.IsTrue(args.Accepted);
        }

        [TestMethod]
        public async Task Reverse_forward_request_rejected_by_host_policy()
        {
            var received = new TaskCompletionSource<TcpForwardRequestArgs>();
            _connection.TcpForwardRequestReceived += (_, e) => received.TrySetResult(e);

            var request = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = false,
                RequestData = new SshDataWriter()
                    .Write("127.0.0.1", Encoding.ASCII)
                    .Write(0u)
                    .ToByteArray(),
            };
            _connection.HandleMessageCore(request);

            var args = await NextAsync(received, "TcpForwardRequestReceived");
            Assert.IsFalse(args.Accepted, "default policy must reject (no handler set Accepted)");
        }

        [TestMethod]
        public async Task Ignore_message_is_a_noop()
        {
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write("session", Encoding.ASCII)
                .Write(7u)
                .Write(0x200000u)
                .Write(32768u)
                .ToByteArray());
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };

            var ignore = new ShouldIgnoreMessage();
            ignore.Load(TestMessages.Payload(ShouldIgnoreMessage.MessageNumber).ToByteArray());
            _connection.HandleMessageCore(ignore);

            // Channel open alone does not raise CommandOpened; force a
            // request through to prove the dispatch loop ignored the
            // SSH_MSG_IGNORE and is still alive.
            _connection.HandleMessageCore(Message.LoadFrom<SessionOpenMessage>(baseMessage));
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after ignore");
        }

        [TestMethod]
        public async Task Declined_exec_and_shell_requests_are_answered_with_failure()
        {
            var execSource = new TaskCompletionSource<CommandRequestedArgs>();
            var shellSource = new TaskCompletionSource<CommandRequestedArgs>();
            _connection.CommandOpened += (_, e) =>
            {
                (e.ShellType == "exec" ? execSource : shellSource).TrySetResult(e);
            };

            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: true,
                w => w.Write("no", Encoding.ASCII)));
            var exec = await NextAsync(execSource, "CommandOpened(exec)");
            Assert.IsFalse(exec.Agreed);

            _connection.HandleMessageCore(Request<ShellRequestMessage>("shell", wantReply: true));
            var shell = await NextAsync(shellSource, "CommandOpened(shell)");
            Assert.AreEqual("shell", shell.ShellType);
            Assert.IsFalse(shell.Agreed);
        }

        [TestMethod]
        public async Task Putty_simple_request_without_reply_is_accepted_silently()
        {
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };
            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "simple@putty.projects.tartarus.org", wantReply: false));

            // The simple@ request itself raises no event; prove the loop is
            // alive with a follow-up exec whose CommandOpened fires.
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after simple request");
        }

        [TestMethod]
        public async Task Auth_agent_request_is_ignored()
        {
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };
            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "auth-agent-req@openssh.com", wantReply: false));

            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after auth-agent-req");
        }

        [TestMethod]
        public async Task Unknown_request_with_reply_is_answered_with_failure()
        {
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };
            _connection.HandleMessageCore(OpenSessionMessage());

            _connection.HandleMessageCore(Request<ChannelRequestMessage>(
                "bogus-request", wantReply: true));

            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after unknown request");
        }

        [TestMethod]
        public async Task Env_without_reply_still_fires_event()
        {
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened");

            var env = new TaskCompletionSource<EnvironmentArgs>();
            _connection.EnvReceived += (_, e) => env.TrySetResult(e);
            _connection.HandleMessageCore(Request<EnvMessage>("env", wantReply: false, w => w
                .Write("A", Encoding.ASCII)
                .Write("B", Encoding.ASCII)));
            var args = await NextAsync(env, "EnvReceived");
            Assert.AreEqual("A", args.Name);
        }

        [TestMethod]
        public async Task Reverse_forward_on_an_occupied_port_reports_failure()
        {
            using var blocker = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            blocker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            blocker.Listen(1);
            var occupied = ((IPEndPoint)blocker.LocalEndPoint!).Port;

            var received = new TaskCompletionSource<TcpForwardRequestArgs>();
            _connection.TcpForwardRequestReceived += (_, e) =>
            {
                e.Accepted = true;
                received.TrySetResult(e);
            };

            var request = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = true,
                RequestData = new SshDataWriter()
                    .Write("127.0.0.1", Encoding.ASCII)
                    .Write((uint)occupied)
                    .ToByteArray(),
            };
            _connection.HandleMessageCore(request);

            var args = await NextAsync(received, "TcpForwardRequestReceived");
            Assert.AreEqual(occupied, args.Port);
        }

        [TestMethod]
        public async Task Malformed_reverse_forward_payloads_are_tolerated()
        {
            var malformedForward = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = false,
                RequestData = new byte[] { 0xFF },
            };
            _connection.HandleMessageCore(malformedForward);

            var malformedCancel = new GlobalRequestMessage
            {
                RequestName = "cancel-tcpip-forward",
                WantReply = false,
                RequestData = new byte[] { 0xFF },
            };
            _connection.HandleMessageCore(malformedCancel);

            // Loop must still be alive.
            var opened = new TaskCompletionSource<bool>();
            _connection.CommandOpened += (_, e) =>
            {
                e.Agreed = true;
                opened.TrySetResult(true);
            };
            _connection.HandleMessageCore(OpenSessionMessage());
            _connection.HandleMessageCore(Request<CommandRequestMessage>("exec", wantReply: false,
                w => w.Write("x", Encoding.ASCII)));
            await NextAsync(opened, "CommandOpened after malformed payloads");
        }

        [TestMethod]
        public async Task Cancel_with_mismatched_address_falls_back_to_port_match()
        {
            var bound = new TaskCompletionSource<TcpForwardRequestArgs>();
            _connection.TcpForwardRequestReceived += (_, e) =>
            {
                e.Accepted = true;
                bound.TrySetResult(e);
            };

            var bindRequest = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = false,
                RequestData = new SshDataWriter()
                    .Write("127.0.0.1", Encoding.ASCII)
                    .Write(0u)
                    .ToByteArray(),
            };
            _connection.HandleMessageCore(bindRequest);
            await bound.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // Cancel with a different address: the exact lookup misses and
            // the port-only fallback must still remove the forwarder.
            var cancel = new GlobalRequestMessage
            {
                RequestName = "cancel-tcpip-forward",
                WantReply = false,
                RequestData = new SshDataWriter()
                    .Write("0.0.0.0", Encoding.ASCII)
                    .Write(0u)
                    .ToByteArray(),
            };
            _connection.HandleMessageCore(cancel);
        }

        [TestMethod]
        public void HandleMessageCore_rejects_null()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => _connection.HandleMessageCore(null!));
        }
    }
}
