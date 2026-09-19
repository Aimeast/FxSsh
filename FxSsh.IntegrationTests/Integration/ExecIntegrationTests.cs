using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    [TestCategory("Integration")]
    [TestClass]
    public sealed class ExecIntegrationTests
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
        public async Task Exec_captures_stdout()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"echo hello-from-exec\"",
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
            StringAssert.Contains(result.StandardOutput, "hello-from-exec");
        }

        [IntegrationTestMethod]
        public async Task Exec_propagates_the_exit_code()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"exit 42\"",
                timeoutMs: 30_000);

            Assert.AreEqual(42, result.ExitCode, $"stderr: {result.StandardError}");
        }

        [IntegrationTestMethod]
        public async Task Exec_stream_is_binary_safe()
        {
            IntegrationGuard.RequireSshClient();
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // The Windows test fixture runs exec through cmd.exe, which
                // has no portable byte-stream generator; the Linux CI job
                // (and WSL runs) cover the binary-safety contract.
                Assert.Inconclusive("binary-safety probe requires a Unix server-side shell");
            }

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"head -c 1048576 /dev/zero | wc -c\"",
                timeoutMs: 60_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
            StringAssert.Contains(result.StandardOutput.Trim(), "1048576");
        }

        [IntegrationTestMethod]
        public async Task Exec_reaches_the_server_handler_with_the_command_text()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            _ = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} \"echo roundtrip\"",
                timeoutMs: 30_000);

            Assert.IsTrue(server.ExecCommands.Count > 0, "no command reached the server");
            StringAssert.Contains(server.ExecCommands[0], "echo roundtrip");
        }
    }
}
