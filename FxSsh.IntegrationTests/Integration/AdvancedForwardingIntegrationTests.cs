using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Direct and reverse forwarding under load: several concurrent forwarded
    /// streams, forced rekeying on the transport, multiple forwards on one
    /// connection, dynamic remote port allocation, dead targets and
    /// half-close propagation.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AdvancedForwardingIntegrationTests
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
            return ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        private static async Task<Socket> ConnectWithRetryAsync(int port, TimeSpan budget)
        {
            var deadline = DateTime.UtcNow + budget;
            Exception? lastError = null;
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(2));
                    return socket;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    await Task.Delay(200);
                }
            }

            throw new TimeoutException($"nothing listened on port {port} within the budget (last error: {lastError?.Message})");
        }

        private static async Task<byte[]> RoundTripAsync(Socket socket, byte[] payload, TimeSpan timeout)
        {
            using var cts = new CancellationTokenSource(timeout);
            var received = new byte[payload.Length];

            var send = Task.Run(async () =>
            {
                var offset = 0;
                while (offset < payload.Length)
                {
                    offset += await socket.SendAsync(
                        payload.AsMemory(offset),
                        SocketFlags.None,
                        cts.Token);
                }
            });

            var read = Task.Run(async () =>
            {
                var offset = 0;
                while (offset < received.Length)
                {
                    var count = await socket.ReceiveAsync(
                        received.AsMemory(offset),
                        SocketFlags.None,
                        cts.Token);
                    if (count == 0)
                        break;
                    offset += count;
                }
                return offset;
            });

            try
            {
                await Task.WhenAll(send, read).WaitAsync(timeout);
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            return received.AsSpan(0, read.Result).ToArray();
        }

        private static async Task<byte[]> ReadExactAsync(Socket socket, int length, TimeSpan timeout)
        {
            using var cts = new CancellationTokenSource(timeout);
            var buffer = new byte[length];
            var offset = 0;
            while (offset < length)
            {
                var read = await socket.ReceiveAsync(
                    buffer.AsMemory(offset),
                    SocketFlags.None,
                    cts.Token);
                if (read == 0)
                    throw new IOException($"socket closed after {offset} of {length} bytes");
                offset += read;
            }
            return buffer;
        }

        private static byte[] RepeatingPattern(int length)
        {
            const string source = "abcdefghijklmnopqrstuvwxyz0123456789\n";
            var result = new byte[length];
            for (var i = 0; i < length; i++)
                result[i] = (byte)source[i % source.Length];
            return result;
        }

        private static void AssertPayload(byte[] actual, byte[] expected)
        {
            Assert.AreEqual(expected.Length, actual.Length, "forwarded byte count differs");
            for (var i = 0; i < expected.Length; i++)
            {
                if (actual[i] != expected[i])
                    Assert.Fail($"forwarded byte differs at offset {i}: expected 0x{expected[i]:X2}, actual 0x{actual[i]:X2}");
            }
        }

        [IntegrationTestMethod]
        public async Task Local_forward_concurrent_large_streams_with_rekey()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-o RekeyLimit=512K -L {localPort}:127.0.0.1:{echo.Port} " +
                OpenSshClient.Target(TestSshServer.Username));

            // CommonOptions sets LogLevel=DEBUG2: a multi-megabyte transfer
            // emits enough debug lines to fill the redirected stderr pipe and
            // stall the client itself. Always drain it.
            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                var payload = RepeatingPattern(2 * 1024 * 1024);
                var clients = new Task[4];
                for (var i = 0; i < clients.Length; i++)
                {
                    clients[i] = Task.Run(async () =>
                    {
                        using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));
                        var echoed = await RoundTripAsync(socket, payload, TimeSpan.FromSeconds(90));
                        AssertPayload(echoed, payload);
                    });
                }

                await Task.WhenAll(clients).WaitAsync(TimeSpan.FromSeconds(180));
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Remote_forward_port_zero_allocates_and_carries_a_large_stream()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            // Win32-OpenSSH 9.5 resets a -R ...:0 forwarded stream shortly
            // after data starts even though the server allocates and
            // advertises the port correctly. Probe the port-zero contract on
            // POSIX clients and keep the large reverse stream on all platforms.
            var requestedPort = OperatingSystem.IsWindows() ? GetFreePort() : 0;

            var errors = new StringBuilder();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -v -N " +
                $"-R 127.0.0.1:{requestedPort}:127.0.0.1:{echo.Port} {OpenSshClient.Target(TestSshServer.Username)}");

            var drain = Task.Run(async () =>
            {
                string? line;
                while ((line = await ssh.StandardError.ReadLineAsync()) != null)
                {
                    lock (errors)
                        errors.AppendLine(line);
                }
            });

            try
            {
                var remotePort = requestedPort == 0
                    ? await WaitForAllocatedPortAsync(ssh, errors, TimeSpan.FromSeconds(20))
                    : requestedPort;
                using var socket = await ConnectWithRetryAsync(remotePort, TimeSpan.FromSeconds(20));
                var payload = RepeatingPattern(4 * 1024 * 1024);
                AssertPayload(await RoundTripAsync(socket, payload, TimeSpan.FromSeconds(120)), payload);
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await drain.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Two_local_forwards_share_one_session()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var firstPort = GetFreePort();
            var secondPort = GetFreePort();
            while (secondPort == firstPort)
                secondPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-L {firstPort}:127.0.0.1:{echo.Port} -L {secondPort}:127.0.0.1:{echo.Port} " +
                OpenSshClient.Target(TestSshServer.Username));

            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                var first = RepeatingPattern(128 * 1024);
                var second = Encoding.ASCII.GetBytes("second-forward-" + Guid.NewGuid().ToString("N"));

                using var firstSocket = await ConnectWithRetryAsync(firstPort, TimeSpan.FromSeconds(20));
                using var secondSocket = await ConnectWithRetryAsync(secondPort, TimeSpan.FromSeconds(20));

                var firstEcho = RoundTripAsync(firstSocket, first, TimeSpan.FromSeconds(60));
                var secondEcho = RoundTripAsync(secondSocket, second, TimeSpan.FromSeconds(60));
                await Task.WhenAll(firstEcho, secondEcho).WaitAsync(TimeSpan.FromSeconds(90));

                AssertPayload(firstEcho.Result, first);
                AssertPayload(secondEcho.Result, second);
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Dynamic_socks_forwarding_round_trip()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-D 127.0.0.1:{localPort} {OpenSshClient.Target(TestSshServer.Username)}");

            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));

                // SOCKS5 greeting: version 5, one method, "no authentication".
                await socket.SendAsync(new byte[] { 0x05, 0x01, 0x00 }, SocketFlags.None);
                var greeting = await ReadExactAsync(socket, 2, TimeSpan.FromSeconds(10));
                CollectionAssert.AreEqual(new byte[] { 0x05, 0x00 }, greeting);

                // CONNECT 127.0.0.1:<echo port>.
                var request = new byte[]
                {
                    0x05, 0x01, 0x00, 0x01, 127, 0x00, 0x00, 0x01,
                    (byte)(echo.Port >> 8), (byte)echo.Port,
                };
                await socket.SendAsync(request, SocketFlags.None);

                var replyHead = await ReadExactAsync(socket, 4, TimeSpan.FromSeconds(10));
                Assert.AreEqual(0x05, replyHead[0], "unexpected SOCKS version");
                Assert.AreEqual(0x00, replyHead[1], "SOCKS CONNECT was refused");
                var addressLength = replyHead[3] switch
                {
                    0x01 => 4,
                    0x04 => 16,
                    0x03 => (await ReadExactAsync(socket, 1, TimeSpan.FromSeconds(10)))[0],
                    var atyp => throw new AssertFailedException($"unexpected SOCKS address type {atyp}"),
                };
                await ReadExactAsync(socket, addressLength + 2, TimeSpan.FromSeconds(10));

                var payload = RepeatingPattern(512 * 1024);
                AssertPayload(await RoundTripAsync(socket, payload, TimeSpan.FromSeconds(60)), payload);
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Local_forward_to_a_dead_target_closes_instead_of_hanging()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localPort = GetFreePort();
            var deadPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-L {localPort}:127.0.0.1:{deadPort} {OpenSshClient.Target(TestSshServer.Username)}");

            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));
                var buffer = new byte[16];
                try
                {
                    var read = await socket.ReceiveAsync(buffer, SocketFlags.None)
                        .WaitAsync(TimeSpan.FromSeconds(15));
                    Assert.AreEqual(0, read, "expected the dead forwarded target to close the connection");
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // Reset is an acceptable close.
                }
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Local_forward_half_close_preserves_tails_at_packet_boundaries()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-o RekeyLimit=256K -L {localPort}:127.0.0.1:{echo.Port} " +
                OpenSshClient.Target(TestSshServer.Username));

            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                // Sizes around the channel packet and window boundaries: the
                // old EOF path dropped the unsent tail when Shutdown raced the
                // send pump.
                var sizes = new[] { 1, 29, 32 * 1024 - 1, 32 * 1024, 32 * 1024 + 1, 128 * 1024, 512 * 1024, 2 * 1024 * 1024 };
                foreach (var size in sizes)
                {
                    using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));
                    var payload = RepeatingPattern(size);

                    var sent = 0;
                    while (sent < payload.Length)
                        sent += await socket.SendAsync(payload.AsMemory(sent), SocketFlags.None);
                    socket.Shutdown(SocketShutdown.Send);

                    using var received = new MemoryStream();
                    var buffer = new byte[32 * 1024];
                    while (true)
                    {
                        var read = await socket.ReceiveAsync(buffer, SocketFlags.None)
                            .WaitAsync(TimeSpan.FromSeconds(60));
                        if (read == 0)
                            break;
                        received.Write(buffer, 0, read);
                    }

                    AssertPayload(received.ToArray(), payload);
                }
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Local_forward_propagates_a_half_closed_stream()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            await using var echo = EchoServer.Start();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localPort = GetFreePort();
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N " +
                $"-L {localPort}:127.0.0.1:{echo.Port} {OpenSshClient.Target(TestSshServer.Username)}");

            var sshError = ssh.StandardError.ReadToEndAsync();

            try
            {
                using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));
                var payload = RepeatingPattern(256 * 1024);
                var sent = 0;
                while (sent < payload.Length)
                    sent += await socket.SendAsync(payload.AsMemory(sent), SocketFlags.None);

                socket.Shutdown(SocketShutdown.Send);

                using var received = new MemoryStream();
                var buffer = new byte[32 * 1024];
                while (true)
                {
                    var read = await socket.ReceiveAsync(buffer, SocketFlags.None)
                        .WaitAsync(TimeSpan.FromSeconds(30));
                    if (read == 0)
                        break;
                    received.Write(buffer, 0, read);
                }

                AssertPayload(received.ToArray(), payload);
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
                try { await sshError.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
            }
        }

        private static async Task<int> WaitForAllocatedPortAsync(Process ssh, StringBuilder errors, TimeSpan budget)
        {
            var deadline = DateTime.UtcNow + budget;
            while (DateTime.UtcNow < deadline)
            {
                lock (errors)
                {
                    var match = Regex.Match(errors.ToString(), @"Allocated port (\d+) for remote forward");
                    if (match.Success)
                        return int.Parse(match.Groups[1].Value);
                }

                if (ssh.HasExited)
                    break;

                await Task.Delay(100);
            }

            lock (errors)
                Assert.Fail($"ssh never reported an allocated remote port:\n{errors}");

            return 0;
        }
    }
}
