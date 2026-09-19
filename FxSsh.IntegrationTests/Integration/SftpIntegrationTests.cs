using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    [TestCategory("Integration")]
    [TestClass]
    public sealed class SftpIntegrationTests
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

        private static string LocalHash(string path)
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }

        [IntegrationTestMethod]
        public async Task Sftp_put_get_round_trip_preserves_content()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localFile = Path.Combine(_tempDir, "upload.bin");
            var expected = new byte[1024 * 1024];
            Random.Shared.NextBytes(expected);
            File.WriteAllBytes(localFile, expected);
            var expectedHash = Convert.ToHexString(SHA256.HashData(expected));

            // Batch commands use bare relative names (no backslash escaping
            // issues) and sftp runs with the temp dir as its local cwd.
            var batch = Path.Combine(_tempDir, "put.sftp");
            File.WriteAllLines(batch, new[] { "put upload.bin remote.bin" });

            var put = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("sftp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -b \"{batch}\" {OpenSshClient.Target(TestSshServer.Username)}",
                timeoutMs: 120_000,
                workingDirectory: _tempDir);
            Assert.AreEqual(0, put.ExitCode, $"stderr: {put.StandardError}");

            Assert.AreEqual(expectedHash, LocalHash(Path.Combine(server.RootPath, "remote.bin")));

            var localCopy = Path.Combine(_tempDir, "download.bin");
            var batchGet = Path.Combine(_tempDir, "get.sftp");
            File.WriteAllLines(batchGet, new[] { "get remote.bin download.bin" });

            var get = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("sftp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -b \"{batchGet}\" {OpenSshClient.Target(TestSshServer.Username)}",
                timeoutMs: 120_000,
                workingDirectory: _tempDir);
            Assert.AreEqual(0, get.ExitCode, $"stderr: {get.StandardError}");

            Assert.AreEqual(expectedHash, LocalHash(localCopy));
        }

        [IntegrationTestMethod]
        public async Task Sftp_directory_operations()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localFile = Path.Combine(_tempDir, "a.txt");
            File.WriteAllText(localFile, "directory ops");

            var batch = Path.Combine(_tempDir, "dirs.sftp");
            File.WriteAllLines(batch, new[]
            {
                "mkdir sub",
                "put a.txt sub/renamed.txt",
                "ls sub",
                "rename sub/renamed.txt sub/moved.txt",
                "rm sub/moved.txt",
                "rmdir sub",
            });

            var result = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("sftp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -b \"{batch}\" {OpenSshClient.Target(TestSshServer.Username)}",
                timeoutMs: 120_000,
                workingDirectory: _tempDir);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
            Assert.IsFalse(Directory.Exists(Path.Combine(server.RootPath, "sub")));
        }

        [IntegrationTestMethod]
        public async Task Sftp_read_only_server_rejects_writes()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync(readOnlySftp: true);
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localFile = Path.Combine(_tempDir, "blocked.txt");
            File.WriteAllText(localFile, "must not land");

            var batch = Path.Combine(_tempDir, "ro.sftp");
            File.WriteAllLines(batch, new[] { "put blocked.txt blocked.txt" });

            var result = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("sftp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -b \"{batch}\" {OpenSshClient.Target(TestSshServer.Username)}",
                timeoutMs: 120_000);

            Assert.AreNotEqual(0, result.ExitCode, "a read-only server must reject puts");
            Assert.IsFalse(File.Exists(Path.Combine(server.RootPath, "blocked.txt")));
        }

        [IntegrationTestMethod]
        public async Task Scp_upload_and_download_preserve_content()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localFile = Path.Combine(_tempDir, "scp-upload.txt");
            File.WriteAllText(localFile, new string('x', 128 * 1024));
            var expectedHash = LocalHash(localFile);

            // Pre-create the remote target so scp's initial remote STAT
            // succeeds: uploading to a *missing* target trips a client-side
            // quirk in both Windows scp builds (they abort silently right
            // after the server's NO_SUCH_FILE status). Real sftp clients are
            // unaffected; only the overwrite path is covered here.
            File.WriteAllText(Path.Combine(server.RootPath, "scp-uploaded.txt"), "placeholder");

            // OpenSSH 9+ runs scp over the SFTP subsystem by default.
            var upload = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("scp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} \"{localFile}\" {OpenSshClient.Target(TestSshServer.Username)}:scp-uploaded.txt",
                timeoutMs: 120_000);
            Assert.AreEqual(0, upload.ExitCode, $"stderr: {upload.StandardError}\nstdout: {upload.StandardOutput}");
            Assert.AreEqual(expectedHash, LocalHash(Path.Combine(server.RootPath, "scp-uploaded.txt")));

            var downloadPath = Path.Combine(_tempDir, "scp-downloaded.txt");
            var download = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("scp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} {OpenSshClient.Target(TestSshServer.Username)}:scp-uploaded.txt \"{downloadPath}\"",
                timeoutMs: 120_000);
            Assert.AreEqual(0, download.ExitCode, $"stderr: {download.StandardError}");
            Assert.AreEqual(expectedHash, LocalHash(downloadPath));
        }
    }
}
