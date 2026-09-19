using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
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

            // Note: Session.StartAsync swallows the version-mismatch
            // SshConnectionException after tearing the connection down, so
            // SshServer.ExceptionRaised does not fire on this path today; the
            // observable contract is the clean TCP close asserted below.
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
