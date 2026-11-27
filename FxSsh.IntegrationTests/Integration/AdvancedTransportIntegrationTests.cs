using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Transport-level scenarios beyond the basic suite: forced rekeying
    /// under every algorithm family, binary and bidirectional streams, slow
    /// readers that exhaust the channel window, many parallel sessions,
    /// Channel multiplexing, malformed peers, and shutdown with live clients.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AdvancedTransportIntegrationTests
    {
        private const int RekeyPayloadSize = 2 * 1024 * 1024;
        private const int LargePayloadSize = 16 * 1024 * 1024;
        private static readonly byte[] Pattern = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");

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

        private static bool IsUnix => !OperatingSystem.IsWindows();

        // GNU yes reports a broken pipe on stderr when head exits; stderr is
        // folded into the channel by the test fixture, so discard it.
        private static string PatternCommand(int length) =>
            $"yes ABCDEFGHIJKLMNOPQRSTUVWXYZ 2>/dev/null | head -c {length}";

        private static byte[] RepeatingPattern(int length)
        {
            var result = new byte[length];
            for (var i = 0; i < result.Length; i++)
                result[i] = Pattern[i % Pattern.Length];
            return result;
        }

        private static int FirstMismatch(byte[] actual)
        {
            for (var i = 0; i < actual.Length; i++)
            {
                if (actual[i] != Pattern[i % Pattern.Length])
                    return i;
            }
            return -1;
        }

        private static void AssertPattern(byte[] actual, int expectedLength)
        {
            Assert.AreEqual(expectedLength, actual.Length, "byte-stream length differs");
            var mismatch = FirstMismatch(actual);
            Assert.AreEqual(-1, mismatch,
                mismatch < 0 ? string.Empty : $"byte-stream differs at offset {mismatch}");
        }

        [IntegrationTestMethod]
        public async Task Rekey_matrix_preserves_binary_streams()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("the pattern generator uses POSIX shell tools");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var kexAlgorithms = new[]
            {
                "curve25519-sha256",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group14-sha256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
            };
            var ciphers = new[] { "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com" };
            var macs = new[]
            {
                "hmac-sha2-256",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512",
                "hmac-sha2-512-etm@openssh.com",
            };
            var hostKeys = new[] { "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512" };

            var cases = new List<(string Name, string Options)>();
            cases.AddRange(kexAlgorithms.Select(kex => ($"kex={kex}", $"-o KexAlgorithms={kex}")));
            cases.AddRange(ciphers.Select(cipher => ($"cipher={cipher}", $"-o Ciphers={cipher}")));
            cases.AddRange(macs.Select(mac => ($"mac={mac}", $"-o Ciphers=aes256-ctr -o MACs={mac}")));
            cases.AddRange(hostKeys.Select(hostKey => ($"hostkey={hostKey}", $"-o HostKeyAlgorithms={hostKey}")));

            var failures = new List<string>();
            foreach (var (name, options) in cases)
            {
                var result = OpenSshClient.SshBinary(
                    $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                    $"-o RekeyLimit=512K {options} {OpenSshClient.Target(TestSshServer.Username)} " +
                    $"\"{PatternCommand(RekeyPayloadSize)}\"",
                    timeoutMs: 120_000);

                if (result.ExitCode != 0)
                {
                    failures.Add($"{name}: exit {result.ExitCode}, stderr: {result.StandardError.Trim()}");
                    continue;
                }

                if (result.StandardOutput.Length != RekeyPayloadSize)
                {
                    failures.Add($"{name}: {result.StandardOutput.Length} bytes instead of {RekeyPayloadSize}");
                    continue;
                }

                var mismatch = FirstMismatch(result.StandardOutput);
                if (mismatch >= 0)
                    failures.Add($"{name}: corrupt byte at offset {mismatch}");
            }

            Assert.AreEqual(0, failures.Count,
                $"forced-rekey matrix failed for {failures.Count}/{cases.Count} cases:\n{string.Join("\n", failures)}");
        }

        [IntegrationTestMethod]
        public async Task Bidirectional_exec_survives_rekey()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("cat-based bidirectional streaming needs a POSIX server shell");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            using var process = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"-o RekeyLimit=256K -o Ciphers=aes128-gcm@openssh.com " +
                $"{OpenSshClient.Target(TestSshServer.Username)} cat");

            var payload = RepeatingPattern(4 * 1024 * 1024);
            using var received = new MemoryStream();
            var readOutput = process.StandardOutput.BaseStream.CopyToAsync(received);
            var readError = process.StandardError.ReadToEndAsync();

            Exception? writeError = null;
            var writeInput = Task.Run(async () =>
            {
                try
                {
                    await process.StandardInput.BaseStream.WriteAsync(payload);
                    await process.StandardInput.BaseStream.FlushAsync();
                }
                catch (Exception ex)
                {
                    writeError = ex;
                }
                finally
                {
                    try { process.StandardInput.Close(); } catch { }
                }
            });

            try
            {
                await Task.WhenAll(writeInput, readOutput).WaitAsync(TimeSpan.FromSeconds(120));
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
            }
            finally
            {
                try { process.Kill(entireProcessTree: true); } catch { }
            }

            var error = await readError;
            Assert.IsNull(writeError, $"writing the upload failed: {writeError}");
            Assert.AreEqual(0, process.ExitCode, $"stderr: {error}");
            AssertPattern(received.ToArray(), payload.Length);
        }

        [IntegrationTestMethod]
        public async Task Slow_reader_resumes_after_channel_window_exhaustion()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("the pattern generator uses POSIX shell tools");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            using var process = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"-o RekeyLimit=4M {OpenSshClient.Target(TestSshServer.Username)} " +
                $"\"{PatternCommand(LargePayloadSize)}\"");

            var readError = process.StandardError.ReadToEndAsync();

            // Do not read stdout for a while: the client's stdout pipe fills,
            // it stops reading the socket, and the server's channel window
            // runs out. Sending must park instead of blocking the message loop.
            await Task.Delay(3_000);

            using var received = new MemoryStream();
            var readOutput = process.StandardOutput.BaseStream.CopyToAsync(received);

            try
            {
                await Task.WhenAll(readOutput).WaitAsync(TimeSpan.FromSeconds(120));
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
            }
            finally
            {
                try { process.Kill(entireProcessTree: true); } catch { }
            }

            var error = await readError;
            Assert.AreEqual(0, process.ExitCode, $"stderr: {error}");
            AssertPattern(received.ToArray(), LargePayloadSize);
        }

        [IntegrationTestMethod]
        public async Task Many_parallel_sessions_all_succeed()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var sessions = Enumerable.Range(0, 12).Select(index => Task.Run(() =>
            {
                var marker = $"parallel-session-{index}";
                var result = OpenSshClient.Ssh(
                    $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                    $"{OpenSshClient.Target(TestSshServer.Username)} \"echo {marker}\"",
                    timeoutMs: 60_000);
                return (marker, result);
            })).ToArray();

            var results = await Task.WhenAll(sessions).WaitAsync(TimeSpan.FromSeconds(120));
            foreach (var (marker, result) in results)
            {
                Assert.AreEqual(0, result.ExitCode, $"{marker} failed: {result.StandardError}");
                StringAssert.Contains(result.StandardOutput, marker);
            }
        }

        [IntegrationTestMethod]
        public async Task One_connection_multiplexes_a_stream_and_short_commands()
        {
            IntegrationGuard.RequireSshClient();
            if (OperatingSystem.IsWindows())
                Assert.Inconclusive("the ControlMaster socket path is POSIX-only in this fixture");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var controlPath = Path.Combine(Path.GetTempPath(), "fxssh-cm-" + Guid.NewGuid().ToString("N"));
            var masterErrors = new StringBuilder();
            using var master = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"-o ControlMaster=yes -o ControlPath=\"{controlPath}\" -o ControlPersist=no -N " +
                OpenSshClient.Target(TestSshServer.Username));

            void DrainMasterErrors()
            {
                string? line;
                while ((line = master.StandardError.ReadLine()) != null)
                {
                    lock (masterErrors)
                        masterErrors.AppendLine(line);
                }
            }

            var masterDrain = Task.Run(DrainMasterErrors);

            try
            {
                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
                var masterReady = false;
                while (DateTime.UtcNow < deadline)
                {
                    if (master.HasExited)
                        break;

                    var check = OpenSshClient.Ssh(
                        $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                        $"-S \"{controlPath}\" -O check {OpenSshClient.Target(TestSshServer.Username)}",
                        timeoutMs: 5_000);

                    if (check.ExitCode == 0)
                    {
                        masterReady = true;
                        break;
                    }

                    await Task.Delay(200);
                }

                lock (masterErrors)
                {
                    Assert.IsTrue(masterReady, $"control master never became ready:\n{masterErrors}");
                }

                var streamTask = Task.Run(() => OpenSshClient.SshBinary(
                    $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                    $"-o RekeyLimit=512K -S \"{controlPath}\" {OpenSshClient.Target(TestSshServer.Username)} " +
                    $"\"{PatternCommand(4 * 1024 * 1024)}\"",
                    timeoutMs: 120_000));

                var shortTasks = Enumerable.Range(0, 5).Select(index => Task.Run(() =>
                {
                    var marker = $"multiplexed-{index}";
                    var result = OpenSshClient.Ssh(
                        $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                        $"-S \"{controlPath}\" {OpenSshClient.Target(TestSshServer.Username)} \"echo {marker}\"",
                        timeoutMs: 60_000);
                    return (marker, result);
                })).ToArray();

                var stream = await streamTask.WaitAsync(TimeSpan.FromSeconds(180));
                Assert.AreEqual(0, stream.ExitCode, $"stream channel failed: {stream.StandardError}");
                AssertPattern(stream.StandardOutput, 4 * 1024 * 1024);

                foreach (var (marker, result) in await Task.WhenAll(shortTasks).WaitAsync(TimeSpan.FromSeconds(120)))
                {
                    Assert.AreEqual(0, result.ExitCode, $"{marker} failed: {result.StandardError}");
                    StringAssert.Contains(result.StandardOutput, marker);
                }
            }
            finally
            {
                try { master.Kill(entireProcessTree: true); } catch { }
                try { await masterDrain.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
                try { File.Delete(controlPath); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Malformed_peers_are_disconnected_without_affecting_new_sessions()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            // A banner longer than the RFC 4253 limit must be rejected.
            using (var socket = await ConnectRawAsync(server.Port))
            {
                await SendRawAsync(socket, Encoding.ASCII.GetBytes(new string('A', 300) + "\r\n"));
                await WaitForPeerCloseAsync(socket);
            }

            // A claiming packet length far beyond the protocol limit must be
            // rejected before any allocation.
            using (var socket = await ConnectRawAsync(server.Port))
            {
                await SendRawAsync(socket, "SSH-2.0-Hostile\r\n"u8.ToArray());
                await SendRawAsync(socket, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 });
                await WaitForPeerCloseAsync(socket);
            }

            // Invalid padding length for the declared packet length.
            using (var socket = await ConnectRawAsync(server.Port))
            {
                await SendRawAsync(socket, "SSH-2.0-Hostile\r\n"u8.ToArray());
                var packet = new byte[21];
                packet[3] = 17;  // packet_length
                packet[4] = 0xFF; // padding_length > packet_length
                await SendRawAsync(socket, packet);
                await WaitForPeerCloseAsync(socket);
            }

            // The server must still accept a normal session afterwards.
            var probe = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"{OpenSshClient.Target(TestSshServer.Username)} \"echo survived-malformed-peers\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, probe.ExitCode, $"stderr: {probe.StandardError}");
            StringAssert.Contains(probe.StandardOutput, "survived-malformed-peers");
        }

        [IntegrationTestMethod]
        public async Task Server_dispose_disconnects_an_active_session()
        {
            IntegrationGuard.RequireSshClient();
            var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            using var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                OpenSshClient.Target(TestSshServer.Username));

            try
            {
                await Task.Delay(750);
                Assert.IsFalse(ssh.HasExited, "the idle session should still be connected before shutdown");

                await server.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15));

                Assert.IsTrue(ssh.WaitForExit(10_000), "the client was not disconnected by server shutdown");
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                await server.DisposeAsync();
            }
        }

        private static async Task<Socket> ConnectRawAsync(int port)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(5));

            using var stream = new NetworkStream(socket, ownsSocket: false);
            var buffer = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
                if (read == 0 || buffer[0] == (byte)'\n')
                    break;
            }

            return socket;
        }

        private static async Task SendRawAsync(Socket socket, byte[] data)
        {
            var offset = 0;
            while (offset < data.Length)
            {
                offset += await socket.SendAsync(data.AsMemory(offset), SocketFlags.None)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(5));
            }
        }

        private static async Task WaitForPeerCloseAsync(Socket socket)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var buffer = new byte[256];
            try
            {
                while (true)
                {
                    var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token);
                    if (read == 0)
                        return;
                }
            }
            catch (OperationCanceledException)
            {
                Assert.Fail("the server kept the malformed connection open");
            }
            catch (SocketException)
            {
                // Reset is a valid close.
            }
        }
    }
}
