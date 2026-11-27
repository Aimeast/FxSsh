using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// SshServer lifecycle behaviour (start/stop/restart/dispose) plus the
    /// transport front door: banner exchange and protocol version rejection,
    /// exercised with a raw TCP client.
    /// </summary>
    [TestClass]
    public sealed class SshServerLifecycleTests
    {
        private static int GetFreePort()
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        private static SshServer CreateServer(int port, string? banner = null)
        {
            var info = banner == null
                ? new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-FxSsh")
                : new StartingInfo(IPAddress.Loopback, port, banner);
            return new SshServer(info);
        }

        [TestMethod]
        public void StartingInfo_has_rfc_compliant_defaults()
        {
            var info = new StartingInfo();

            Assert.AreEqual(IPAddress.IPv6Any, info.LocalAddress);
            Assert.AreEqual(22, info.Port);
            Assert.AreEqual("SSH-2.0-FxSsh", info.ServerBanner);
        }

        [TestMethod]
        public void Start_twice_throws_and_stop_allows_restart()
        {
            using var server = CreateServer(GetFreePort());
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));

            server.Start();
            Assert.ThrowsExactly<InvalidOperationException>(() => server.Start());

            server.Stop();
            server.Stop(); // stopping a stopped server is a no-op

            server.Start(); // restart after stop is supported
            server.Stop();
        }

        [TestMethod]
        public async Task StartAsync_failure_leaves_the_server_restartable()
        {
            // TEST-NET-1 is never assigned to a local interface, so both
            // attempts fail in the bind. The second must fail with the same
            // SocketException, not "already started": a failed Start must not
            // flip the state machine.
            using var server = new SshServer(new StartingInfo(
                IPAddress.Parse("192.0.2.1"), GetFreePort(), "SSH-2.0-FxSsh"));
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));

            await Assert.ThrowsExactlyAsync<SocketException>(() => server.StartAsync());
            await Assert.ThrowsExactlyAsync<SocketException>(() => server.StartAsync());
        }

        [TestMethod]
        public async Task StopAsync_closes_active_client_connections()
        {
            var port = GetFreePort();
            using var server = CreateServer(port);
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            await server.StartAsync();

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));
            Assert.AreEqual("SSH-2.0-FxSsh", await ReadLineAsync(client));

            await server.StopAsync();

            var buffer = new byte[16];
            var read = await client.ReceiveAsync(buffer, SocketFlags.None).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.AreEqual(0, read, "StopAsync must close accepted sessions");
        }

        [TestMethod]
        public void Dispose_marks_the_server_unusable()
        {
            var server = CreateServer(GetFreePort());
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            server.Start();

            server.Dispose();
            server.Dispose(); // idempotent

            Assert.ThrowsExactly<ObjectDisposedException>(server.Start);
            Assert.ThrowsExactly<ObjectDisposedException>(server.Stop);
        }

        [TestMethod]
        public void Stop_without_start_is_a_noop()
        {
            using var server = CreateServer(GetFreePort());
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));

            server.Stop();
        }

        [TestMethod]
        public void AddHostKey_rejects_null_and_ignores_duplicates()
        {
            using var server = CreateServer(GetFreePort());
            var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");

            Assert.ThrowsExactly<ArgumentNullException>(() => server.AddHostKey("ecdsa-sha2-nistp256", null!));
            Assert.ThrowsExactly<ArgumentNullException>(() => server.AddHostKey(null!, pem));

            server.AddHostKey("ecdsa-sha2-nistp256", pem);
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
        }

        [TestMethod]
        public async Task Start_requires_at_least_one_host_key()
        {
            using var server = CreateServer(GetFreePort());

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => server.StartAsync());
        }

        [TestMethod]
        public async Task Start_rejects_a_host_key_with_the_wrong_curve()
        {
            using var server = CreateServer(GetFreePort());
            // P-384 key registered under the P-256 algorithm name would
            // advertise a malformed host key blob to every client.
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp384"));

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => server.StartAsync());
        }

        [TestMethod]
        public async Task Server_sends_banner_and_accepts_connections()
        {
            var port = GetFreePort();
            using var server = CreateServer(port, "SSH-2.0-FxSsh-Test");
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));

            var accepted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            server.ConnectionAccepted += (_, _) => accepted.TrySetResult();

            server.Start();

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(new IPEndPoint(IPAddress.Loopback, port));

            var banner = await ReadLineAsync(client);
            Assert.AreEqual("SSH-2.0-FxSsh-Test", banner);

            await accepted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }

        [TestMethod]
        public async Task Invalid_protocol_version_is_rejected()
        {
            var port = GetFreePort();
            using var server = CreateServer(port, "SSH-2.0-FxSsh-Test");
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));

            // The version mismatch is a protocol error: the session tears the
            // connection down and surfaces the exception to the host without
            // sending internal error text to the peer.
            var raised = new TaskCompletionSource<Exception>();
            server.ExceptionRaised += (_, ex) => raised.TrySetResult(ex);
            server.Start();

            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(new IPEndPoint(IPAddress.Loopback, port));

            _ = await ReadLineAsync(client); // server banner
            var badVersion = Encoding.ASCII.GetBytes("SSH-1.5-not-supported\r\n");
            await client.SendAsync(badVersion, SocketFlags.None);

            // The server closes the connection after the version mismatch.
            var buffer = new byte[64];
            var receive = client.ReceiveAsync(buffer, SocketFlags.None);
            var completed = await Task.WhenAny(receive, Task.Delay(10_000));
            Assert.AreSame(receive, completed, "the server never closed the connection");
            Assert.AreEqual(0, receive.Result, "expected a clean shutdown (0 bytes)");

            var error = await raised.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType<SshConnectionException>(error);
        }

        [TestMethod]
        public async Task InactivityTimeout_reaps_a_session_that_never_completes_the_handshake()
        {
            var port = GetFreePort();
            using var server = CreateServer(port);
            server.InactivityTimeout = TimeSpan.FromMilliseconds(300);
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            await server.StartAsync();

            try
            {
                using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));

                // The client stays silent: after the server-side banner and
                // KEXINIT burst, the inactivity timeout must close the
                // connection on its own (the disconnect arrives as data
                // first, then a clean EOF).
                var buffer = new byte[4096];
                var total = 0;
                while (true)
                {
                    int received;
                    try
                    {
                        received = await client.ReceiveAsync(buffer, SocketFlags.None).WaitAsync(TimeSpan.FromSeconds(5));
                    }
                    catch (TimeoutException)
                    {
                        Assert.Fail("the server never closed the idle connection");
                        return;
                    }

                    if (received == 0)
                        break;

                    total += received;
                }

                Assert.IsTrue(total > 0, "expected at least the server banner before the disconnect");
            }
            finally
            {
                await server.StopAsync();
            }
        }

        [TestMethod]
        public async Task Without_InactivityTimeout_a_silent_connection_is_kept()
        {
            var port = GetFreePort();
            using var server = CreateServer(port);
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            await server.StartAsync();

            try
            {
                using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port));

                // Drain whatever the server sends up front (banner, KEXINIT)
                // for one second. A 0-byte read would mean the server closed
                // the connection, which must not happen without a timeout.
                var buffer = new byte[4096];
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
                while (DateTime.UtcNow < deadline)
                {
                    using var slice = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                    int received;
                    try
                    {
                        received = await client.ReceiveAsync(buffer, SocketFlags.None, slice.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        continue; // nothing arrived in this slice - still open
                    }

                    Assert.AreNotEqual(0, received, "connection was closed although no InactivityTimeout is configured");
                }
            }
            finally
            {
                await server.StopAsync();
            }
        }

        private static async Task<string> ReadLineAsync(Socket socket)
        {
            var buffer = new List<byte>();
            var one = new byte[1];
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);

            while (DateTime.UtcNow < deadline)
            {
                var received = await socket.ReceiveAsync(one, SocketFlags.None).WaitAsync(TimeSpan.FromSeconds(5));
                if (received == 0)
                    break;

                if (one[0] == '\n')
                {
                    var line = Encoding.ASCII.GetString([.. buffer]);
                    return line.EndsWith("\r") ? line[..^1] : line;
                }

                buffer.Add(one[0]);
            }

            throw new TimeoutException("no complete line received in time");
        }
    }
}
