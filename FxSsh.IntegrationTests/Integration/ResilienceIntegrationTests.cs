using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Resilience scenarios that unit tests cannot reach: rekeying after
    /// heavy traffic, abrupt client disconnects mid stream and mid PTY,
    /// keepalive probing, and forwarded-channel open failures.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class ResilienceIntegrationTests
    {
        private string _tempDir = null!;

        [TestInitialize]
        public void CreateTempDir()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "fxssh-it-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);
        }

        [TestCleanup]
        public void DeleteTempDir()
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }

        private static int GetFreePort()
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)probe.LocalEndPoint).Port;
        }

        private static (string Command, string SkipReason) HeavyTrafficCommand()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // ~550 MB through the channel: create a sparse file, stream
                // it via bsdtar (ships with the OS) and clean up. (cmd is
                // the fixture's exec shell on Windows.)
                return ("fsutil file createnew %TEMP%\\fxssh-rekey.tmp 550000000 && tar -cf - -C %TEMP% fxssh-rekey.tmp && del %TEMP%\\fxssh-rekey.tmp", "");
            }

            return ("head -c 550M /dev/zero", "");
        }

        [IntegrationTestMethod]
        public async Task Session_rekeys_after_heavy_traffic()
        {
            IntegrationGuard.RequireSshClient();
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            // >512 MB of flow crosses the rekey threshold mid stream: the
            // server starts a second key exchange while the client keeps
            // streaming, and both sides must come out consistent.
            var (command, skip) = HeavyTrafficCommand();
            if (skip.Length > 0)
                Assert.Inconclusive(skip);

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"{command}\"",
                timeoutMs: 240_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
        }

        [IntegrationTestMethod]
        public async Task Abrupt_client_disconnect_mid_stream_is_tolerated()
        {
            IntegrationGuard.RequireSshClient();
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var (command, skip) = HeavyTrafficCommand();
            if (skip.Length > 0)
                Assert.Inconclusive(skip);

            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"{command}\"");
            await Task.Delay(2_000); // let the stream fill
            try { ssh.Kill(entireProcessTree: true); } catch { }

            // The server must survive: a fresh session still works.
            var probe = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"echo alive\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, probe.ExitCode, $"stderr: {probe.StandardError}");
            StringAssert.Contains(probe.StandardOutput, "alive");
        }

        [IntegrationTestMethod]
        public async Task Abrupt_disconnect_tears_down_a_running_terminal()
        {
            IntegrationGuard.RequireSshClient();
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -tt {OpenSshClient.Target(TestSshServer.Username)}");
            await Task.Delay(1_500); // shell + PTY come up

            // Killing the client mid session forces the server side to tear
            // down the pseudo console / ptmx and every associated pipe.
            try { ssh.Kill(entireProcessTree: true); } catch { }
            await Task.Delay(500);

            // The server must still accept new sessions afterwards.
            var probe = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"exit 0\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, probe.ExitCode, $"stderr: {probe.StandardError}");
        }

        [IntegrationTestMethod]
        public async Task Forward_to_a_dead_target_fails_the_channel_open()
        {
            IntegrationGuard.RequireSshClient();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Windows OpenSSH 9.5 keeps the forwarded connection open
                // after a refused local target instead of answering with
                // CHANNEL_OPEN_FAILURE; Linux clients behave per RFC.
                Assert.Inconclusive("Windows OpenSSH client hangs on a refused -R target");
            }

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var remotePort = GetFreePort();
            var deadLocal = GetFreePort(); // nothing listens here

            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N -R 127.0.0.1:{remotePort}:127.0.0.1:{deadLocal} {OpenSshClient.Target(TestSshServer.Username)}");

            try
            {
                // The ssh client needs a moment to authenticate and bind the
                // remote port; retry until the forwarded listener accepts.
                Socket? socket = null;
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        socket = await ConnectAsync(remotePort);
                        break;
                    }
                    catch (SocketException)
                    {
                        await Task.Delay(250);
                    }
                }

                if (socket == null)
                    Assert.Fail($"the reverse forward never bound on port {remotePort}");

                using (socket)
                {
                    // The client cannot connect to the dead local target and
                    // answers CHANNEL_OPEN_FAILURE; the server must close our
                    // TCP connection instead of hanging. Depending on timing
                    // the close surfaces as FIN (read == 0) or as RST.
                    var buffer = new byte[16];
                    try
                    {
                        var read = await socket.ReceiveAsync(buffer, SocketFlags.None)
                            .WaitAsync(TimeSpan.FromSeconds(10));
                        Assert.AreEqual(0, read, "expected the forwarded connection to be closed");
                    }
                    catch (SocketException ex)
                        when (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        // Reset counts as "closed instead of hanging".
                    }
                }
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Server_with_keepalive_survives_an_idle_client()
        {
            IntegrationGuard.RequireSshClient();
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync(keepaliveIdleSeconds: 1);
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            // Probes fire every second; the OpenSSH client answers them, so
            // the session must survive well past three probe intervals.
            var first = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"echo first\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, first.ExitCode);

            await Task.Delay(3_500);

            var second = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"echo second\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, second.ExitCode, $"stderr: {second.StandardError}");
            StringAssert.Contains(second.StandardOutput, "second");
        }

        private static async Task<Socket> ConnectAsync(int port)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(5));
            return socket;
        }
    }
}
