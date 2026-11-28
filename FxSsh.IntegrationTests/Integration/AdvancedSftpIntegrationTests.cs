using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// SFTP and scp scenarios that exercise the real client end to end:
    /// multi-megabyte transfers, concurrent sessions, read-only enforcement,
    /// Unicode/zero-byte files, and the symlink/absolute-path jail.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AdvancedSftpIntegrationTests
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

        private static bool IsUnix => !OperatingSystem.IsWindows();

        private static string LocalHash(string path)
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }

        private static OpenSshClient.RunResult RunSftp(
            TestSshServer server,
            string key,
            string workingDirectory,
            params string[] commands)
        {
            var batch = Path.Combine(workingDirectory, "batch-" + Guid.NewGuid().ToString("N") + ".sftp");
            File.WriteAllLines(batch, commands);
            // Force frequent rekeys: SFTP responses, window adjustments and
            // the data stream must stay consistent across a key switch.
            return OpenSshClient.RunProcess(
                OpenSshClient.FindTool("sftp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} " +
                $"-o RekeyLimit=512K -b \"{batch}\" {OpenSshClient.Target(TestSshServer.Username)}",
                timeoutMs: 240_000,
                workingDirectory: workingDirectory);
        }

        private static string WriteRandomFile(string path, int length)
        {
            var bytes = new byte[length];
            Random.Shared.NextBytes(bytes);
            File.WriteAllBytes(path, bytes);
            return Convert.ToHexString(SHA256.HashData(bytes));
        }

        [IntegrationTestMethod]
        public async Task Sftp_large_file_round_trip_preserves_content()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localFile = Path.Combine(_tempDir, "large-upload.bin");
            var expectedHash = WriteRandomFile(localFile, 8 * 1024 * 1024);

            var put = RunSftp(server, key, _tempDir, "put large-upload.bin large-remote.bin");
            Assert.AreEqual(0, put.ExitCode, $"put stderr: {put.StandardError}");
            Assert.AreEqual(expectedHash, LocalHash(Path.Combine(server.RootPath, "large-remote.bin")));

            var get = RunSftp(server, key, _tempDir, "get large-remote.bin large-download.bin");
            Assert.AreEqual(0, get.ExitCode, $"get stderr: {get.StandardError}");
            Assert.AreEqual(expectedHash, LocalHash(Path.Combine(_tempDir, "large-download.bin")));
        }

        [IntegrationTestMethod]
        public async Task Sftp_handles_unicode_and_empty_files()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("Windows sftp applies the console code page to batch-file names");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var localUnicode = Path.Combine(_tempDir, "unicodé-测试.txt");
            File.WriteAllText(localUnicode, "unicode payload", new UTF8Encoding(false));
            var localEmpty = Path.Combine(_tempDir, "empty.bin");
            File.WriteAllBytes(localEmpty, []);

            var upload = RunSftp(server, key, _tempDir,
                "put unicodé-测试.txt 远程-测试.txt",
                "put empty.bin empty-remote.bin");
            Assert.AreEqual(0, upload.ExitCode, $"stderr: {upload.StandardError}");

            Assert.AreEqual("unicode payload", File.ReadAllText(Path.Combine(server.RootPath, "远程-测试.txt")));
            Assert.AreEqual(0L, new FileInfo(Path.Combine(server.RootPath, "empty-remote.bin")).Length);

            var download = RunSftp(server, key, _tempDir,
                "get 远程-测试.txt unicode-down.txt",
                "get empty-remote.bin empty-down.bin");
            Assert.AreEqual(0, download.ExitCode, $"stderr: {download.StandardError}");
            Assert.AreEqual("unicode payload", File.ReadAllText(Path.Combine(_tempDir, "unicode-down.txt")));
            Assert.AreEqual(0L, new FileInfo(Path.Combine(_tempDir, "empty-down.bin")).Length);
        }

        [IntegrationTestMethod]
        public async Task Sftp_symlink_inside_the_jail_is_followed_but_escape_is_rejected()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var realFile = Path.Combine(server.RootPath, "real.txt");
            File.WriteAllText(realFile, "inside-the-jail");

            var outsideDir = Path.Combine(_tempDir, "outside");
            Directory.CreateDirectory(outsideDir);
            var outsideFile = Path.Combine(outsideDir, "secret.txt");
            var secret = "outside-secret-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(outsideFile, secret);

            var insideLink = Path.Combine(server.RootPath, "inside-link.txt");
            var escapeLink = Path.Combine(server.RootPath, "escape-link.txt");
            try
            {
                File.CreateSymbolicLink(insideLink, realFile);
                File.CreateSymbolicLink(escapeLink, outsideFile);
            }
            catch (UnauthorizedAccessException)
            {
                Assert.Inconclusive("creating file symlinks requires a privilege this Windows account lacks");
                return;
            }
            catch (IOException)
            {
                Assert.Inconclusive("creating file symlinks requires a privilege this Windows account lacks");
                return;
            }

            var inside = RunSftp(server, key, _tempDir, "get inside-link.txt inside-copy.txt");
            Assert.AreEqual(0, inside.ExitCode, $"following an internal link failed: {inside.StandardError}");
            Assert.AreEqual("inside-the-jail", File.ReadAllText(Path.Combine(_tempDir, "inside-copy.txt")));

            var escape = RunSftp(server, key, _tempDir, "get escape-link.txt escaped.txt");
            Assert.AreNotEqual(0, escape.ExitCode, "a link escaping the root must not be readable");
            Assert.IsFalse(File.Exists(Path.Combine(_tempDir, "escaped.txt")));
            Assert.IsFalse(File.Exists(Path.Combine(server.RootPath, "escaped.txt")));
        }

        [IntegrationTestMethod]
        public async Task Sftp_absolute_paths_cannot_escape_the_root()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("absolute Unix path handling is exercised on Linux/WSL");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var outsideFile = Path.Combine(_tempDir, "absolute-outside.txt");
            File.WriteAllText(outsideFile, "must-not-leak");

            var result = RunSftp(server, key, _tempDir, $"get \"{outsideFile}\" absolute-copy.txt");

            Assert.AreNotEqual(0, result.ExitCode, "an absolute path outside the root must be rejected");
            Assert.IsFalse(File.Exists(Path.Combine(_tempDir, "absolute-copy.txt")));
            Assert.IsFalse(File.Exists(Path.Combine(server.RootPath, "absolute-copy.txt")));

            // A relative ".." component must be resolved inside the jail and
            // rejected when it points above the root.
            var parentFile = Path.Combine(
                Path.GetDirectoryName(server.RootPath)!,
                "parent-secret-" + Guid.NewGuid().ToString("N") + ".txt");
            File.WriteAllText(parentFile, "parent-secret");
            try
            {
                var parent = RunSftp(server, key, _tempDir,
                    $"get ../{Path.GetFileName(parentFile)} parent-copy.txt");
                Assert.AreNotEqual(0, parent.ExitCode, "a '..' path above the root must be rejected");
                Assert.IsFalse(File.Exists(Path.Combine(_tempDir, "parent-copy.txt")));
                Assert.IsFalse(File.Exists(Path.Combine(server.RootPath, "parent-copy.txt")));
            }
            finally
            {
                try { File.Delete(parentFile); } catch { }
            }
        }

        [IntegrationTestMethod]
        public async Task Sftp_directory_symlink_escape_is_rejected()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var outsideDir = Path.Combine(_tempDir, "outside-directory");
            Directory.CreateDirectory(outsideDir);
            File.WriteAllText(Path.Combine(outsideDir, "secret.txt"), "outside-directory-secret");

            var link = Path.Combine(server.RootPath, "escape-dir");
            try
            {
                Directory.CreateSymbolicLink(link, outsideDir);
            }
            catch (UnauthorizedAccessException)
            {
                Assert.Inconclusive("creating directory symlinks requires a privilege this Windows account lacks");
                return;
            }
            catch (IOException)
            {
                Assert.Inconclusive("creating directory symlinks requires a privilege this Windows account lacks");
                return;
            }

            var result = RunSftp(server, key, _tempDir, "get escape-dir/secret.txt escaped-directory.txt");
            Assert.AreNotEqual(0, result.ExitCode, "a directory link escaping the root must not be traversable");
            Assert.IsFalse(File.Exists(Path.Combine(_tempDir, "escaped-directory.txt")));
        }

        [IntegrationTestMethod]
        public async Task Sftp_chmod_updates_the_real_file_mode()
        {
            IntegrationGuard.RequireSshClient();
            if (OperatingSystem.IsWindows())
            {
                Assert.Inconclusive("POSIX mode bits are not exposed by Windows");
                return;
            }

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var path = Path.Combine(server.RootPath, "mode.txt");
            File.WriteAllText(path, "mode");

            var result = RunSftp(server, key, _tempDir, "chmod 640 mode.txt");
            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");

            var expected = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
            Assert.AreEqual(expected, File.GetUnixFileMode(path));
        }

        [IntegrationTestMethod]
        public async Task Sftp_read_only_rejects_every_mutation()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync(readOnlySftp: true);
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var existing = Path.Combine(server.RootPath, "existing.txt");
            File.WriteAllText(existing, "original");
            var local = Path.Combine(_tempDir, "local.txt");
            File.WriteAllText(local, "replacement");

            var mutations = new[]
            {
                "put local.txt existing.txt",
                "mkdir new-dir",
                "rename existing.txt moved.txt",
                "rm existing.txt",
                "chmod 600 existing.txt",
            };

            foreach (var mutation in mutations)
            {
                var result = RunSftp(server, key, _tempDir, mutation);
                Assert.AreNotEqual(0, result.ExitCode, $"read-only server accepted: {mutation}");
            }

            Assert.AreEqual("original", File.ReadAllText(existing));
            Assert.IsFalse(File.Exists(Path.Combine(server.RootPath, "moved.txt")));
            Assert.IsFalse(Directory.Exists(Path.Combine(server.RootPath, "new-dir")));
        }

        [IntegrationTestMethod]
        public async Task Sftp_concurrent_sessions_transfer_independently()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var hashes = new string[4];
            for (var i = 0; i < hashes.Length; i++)
                hashes[i] = WriteRandomFile(Path.Combine(_tempDir, $"concurrent-{i}.bin"), 2 * 1024 * 1024);

            var transfers = new Task[hashes.Length];
            for (var i = 0; i < hashes.Length; i++)
            {
                var index = i;
                transfers[i] = Task.Run(() =>
                {
                    var result = RunSftp(server, key, _tempDir,
                        $"put concurrent-{index}.bin concurrent-remote-{index}.bin");
                    Assert.AreEqual(0, result.ExitCode, $"transfer {index}: {result.StandardError}");
                });
            }

            await Task.WhenAll(transfers).WaitAsync(TimeSpan.FromSeconds(300));

            for (var i = 0; i < hashes.Length; i++)
                Assert.AreEqual(hashes[i], LocalHash(Path.Combine(server.RootPath, $"concurrent-remote-{i}.bin")));
        }

        [IntegrationTestMethod]
        public async Task Scp_uploads_a_new_file_and_a_directory_tree()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("Windows scp aborts on a missing remote target (covered elsewhere)");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            // -s forces the SFTP protocol on clients older than OpenSSH 9
            // (e.g. 8.9 on ubuntu-22.04), which default to a remote "scp -t".
            var newFile = Path.Combine(_tempDir, "scp-new.bin");
            var expectedHash = WriteRandomFile(newFile, 1024 * 1024);

            var upload = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("scp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -s " +
                $"\"{newFile}\" {OpenSshClient.Target(TestSshServer.Username)}:scp-new.bin",
                timeoutMs: 120_000);
            Assert.AreEqual(0, upload.ExitCode, $"stderr: {upload.StandardError}");
            Assert.AreEqual(expectedHash, LocalHash(Path.Combine(server.RootPath, "scp-new.bin")));

            var tree = Path.Combine(_tempDir, "tree");
            Directory.CreateDirectory(Path.Combine(tree, "sub"));
            File.WriteAllText(Path.Combine(tree, "a.txt"), "tree-a");
            File.WriteAllText(Path.Combine(tree, "sub", "b.bin"), "tree-b");

            var recursive = OpenSshClient.RunProcess(
                OpenSshClient.FindTool("scp")!,
                $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} -s -r " +
                $"\"{tree}\" {OpenSshClient.Target(TestSshServer.Username)}:tree-copy",
                timeoutMs: 120_000);
            Assert.AreEqual(0, recursive.ExitCode, $"stderr: {recursive.StandardError}");
            Assert.AreEqual("tree-a", File.ReadAllText(Path.Combine(server.RootPath, "tree-copy", "a.txt")));
            Assert.AreEqual("tree-b", File.ReadAllText(Path.Combine(server.RootPath, "tree-copy", "sub", "b.bin")));
        }

        [IntegrationTestMethod]
        public async Task Abrupt_sftp_upload_leaves_the_server_healthy()
        {
            IntegrationGuard.RequireSshClient();
            if (!IsUnix)
                Assert.Inconclusive("large sparse-file setup is Linux-specific");

            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add("*");

            var large = Path.Combine(_tempDir, "abrupt.bin");
            using (var stream = File.Create(large))
                stream.SetLength(256L * 1024 * 1024);

            var batch = Path.Combine(_tempDir, "abrupt.sftp");
            File.WriteAllText(batch, "put abrupt.bin abrupt-remote.bin\n");
            var psi = new ProcessStartInfo
            {
                FileName = OpenSshClient.FindTool("sftp")!,
                Arguments = $"{OpenSshClient.CommonOptions(server.Port, key, fileTransferTool: true)} " +
                    $"-b \"{batch}\" {OpenSshClient.Target(TestSshServer.Username)}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
                WorkingDirectory = _tempDir,
            };

            using var sftp = Process.Start(psi) ?? throw new InvalidOperationException("failed to start sftp");
            await Task.Delay(500);
            try { sftp.Kill(entireProcessTree: true); } catch { }

            // The server must tear the partial upload down and accept a new
            // session without waiting for the abandoned transfer.
            var probe = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"{OpenSshClient.Target(TestSshServer.Username)} \"echo after-abrupt-sftp\"",
                timeoutMs: 30_000);
            Assert.AreEqual(0, probe.ExitCode, $"stderr: {probe.StandardError}");
            StringAssert.Contains(probe.StandardOutput, "after-abrupt-sftp");
        }
    }
}
