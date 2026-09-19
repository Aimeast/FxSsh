using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    [TestCategory("Integration")]
    [TestClass]
    public sealed class PortForwardingIntegrationTests
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

        /// <summary>A tiny echo TCP server: replies with exactly what it receives.</summary>
        private static async Task<(TcpListener Listener, int Port)> StartEchoServerAsync()
        {
            // Parallel tests race for probed free ports; retry on bind failure.
            for (var attempt = 0; ; attempt++)
            {
                var listener = new TcpListener(IPAddress.Loopback, GetFreePort());
                try
                {
                    listener.Start();
                }
                catch (SocketException) when (attempt < 20)
                {
                    Thread.Sleep(50);
                    continue;
                }

                _ = Task.Run(async () =>
                {
                    while (true)
                    {
                        try
                        {
                            using var client = await listener.AcceptTcpClientAsync();
                            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                            var buffer = new byte[4096];
                            while (true)
                            {
                                var read = await client.Client.ReceiveAsync(buffer, SocketFlags.None, cts.Token);
                                if (read == 0)
                                    break;
                                await client.Client.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, cts.Token);
                            }
                        }
                        catch
                        {
                            // Accept loop terminated or a client timed out.
                        }
                    }
                });

                return (listener, ((IPEndPoint)listener.LocalEndpoint).Port);
            }
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
                    await socket.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromSeconds(1));
                    return socket;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    await Task.Delay(250);
                }
            }

            throw new TimeoutException($"nothing listened on port {port} within the budget (last error: {lastError?.Message})");
        }

        private static async Task<string> EchoExchange(Socket socket, string payload)
        {
            var sent = Encoding.ASCII.GetBytes(payload);
            await socket.SendAsync(sent, SocketFlags.None);

            var received = new byte[sent.Length];
            var total = 0;
            while (total < received.Length)
            {
                var read = await socket.ReceiveAsync(received.AsMemory(total), SocketFlags.None).AsTask().WaitAsync(TimeSpan.FromSeconds(15));
                if (read == 0)
                    break;
                total += read;
            }

            return Encoding.ASCII.GetString(received, 0, total);
        }

        [IntegrationTestMethod]
        public async Task Local_forwarding_round_trip()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var (_, echoPort) = await StartEchoServerAsync();
            var localPort = GetFreePort();

            var payload = $"ping-local-{Guid.NewGuid():N}";
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N -L {localPort}:127.0.0.1:{echoPort} {OpenSshClient.Target(TestSshServer.Username)}");

            try
            {
                using var socket = await ConnectWithRetryAsync(localPort, TimeSpan.FromSeconds(20));
                Assert.AreEqual(payload, await EchoExchange(socket, payload));
            }
            finally
            {
                try { ssh.Kill(entireProcessTree: true); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Remote_forwarding_round_trip()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var (_, echoPort) = await StartEchoServerAsync();
            var payload = $"ping-remote-{Guid.NewGuid():N}";

            // The probed remote port can be stolen by a parallel test before
            // the server's forwarding listener binds it; retry with a fresh
            // port on timeout.
            var sshErrors = new StringBuilder();
            for (var attempt = 0; ; attempt++)
            {
                var remotePort = GetFreePort();
                var ssh = OpenSshClient.StartSsh(
                    $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -N -R 127.0.0.1:{remotePort}:127.0.0.1:{echoPort} {OpenSshClient.Target(TestSshServer.Username)}");
                ssh.ErrorDataReceived += (_, e) =>
                {
                    lock (sshErrors)
                        sshErrors.AppendLine(e.Data);
                };
                ssh.BeginErrorReadLine();

                try
                {
                    using var socket = await ConnectWithRetryAsync(remotePort, TimeSpan.FromSeconds(20));
                    Assert.AreEqual(payload, await EchoExchange(socket, payload));
                    return;
                }
                catch (TimeoutException) when (attempt < 2)
                {
                    // Fall through and retry with a new port.
                    await Task.Delay(100);
                }
                catch (TimeoutException)
                {
                    lock (sshErrors)
                    {
                        Assert.Fail($"remote forwarding did not relay data. ssh stderr:\n{sshErrors}");
                    }
                }
                finally
                {
                    try { ssh.Kill(entireProcessTree: true); } catch { }
                }
            }
        }
    }
}
