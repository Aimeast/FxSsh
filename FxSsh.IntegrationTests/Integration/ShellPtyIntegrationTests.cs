using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Interactive shell over a real PTY (ConPTY on Windows, ptmx on
    /// Linux/WSL): type a command into ssh -tt and read the echoed output.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class ShellPtyIntegrationTests
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

        [IntegrationTestMethod]
        public async Task Interactive_shell_echoes_command_output()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var marker = "FXSSH_PTY_" + Guid.NewGuid().ToString("N")[..12];
            var ssh = OpenSshClient.StartSsh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes -tt {OpenSshClient.Target(TestSshServer.Username)}");

            var outputBuilder = new StringBuilder();
            var receivedMarker = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var outputLock = new object();

            ssh.OutputDataReceived += (_, e) =>
            {
                lock (outputLock)
                {
                    outputBuilder.Append(e.Data);
                    if (outputBuilder.ToString().Contains(marker))
                        receivedMarker.TrySetResult();
                }
            };

            ssh.ErrorDataReceived += (_, e) =>
            {
                lock (outputLock)
                {
                    outputBuilder.Append(e.Data);
                }
            };

            ssh.BeginOutputReadLine();
            ssh.BeginErrorReadLine();

            // The shell is ready once the prompt appears; typing straight
            // away also works because the PTY buffers input.
            var command = OperatingSystem.IsWindows() ? $"echo {marker}\r\n" : $"echo {marker}\n";
            await ssh.StandardInput.WriteAsync(command);
            await ssh.StandardInput.FlushAsync();
            await Task.Delay(500);
            await ssh.StandardInput.WriteAsync(OperatingSystem.IsWindows() ? "exit\r\n" : "exit\n");
            await ssh.StandardInput.FlushAsync();

            var finished = await Task.WhenAny(receivedMarker.Task, Task.Delay(30_000));

            try { ssh.Kill(entireProcessTree: true); } catch { }

            if (finished != receivedMarker.Task)
            {
                string captured;
                lock (outputLock)
                {
                    captured = outputBuilder.ToString();
                }

                Assert.Fail($"marker never appeared in the PTY stream. Captured output:\n{Truncate(captured)}");
            }
        }

        private static string Truncate(string value) =>
            value.Length <= 4000 ? value : value[..4000] + "...(truncated)";
    }
}
