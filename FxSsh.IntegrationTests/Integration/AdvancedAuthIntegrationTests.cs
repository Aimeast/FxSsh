using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Authentication combinations with real keys and passwords: RSA keys,
    /// unsupported key types, wrong usernames, publickey-to-password
    /// fallback, and repeated failures followed by a successful login.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AdvancedAuthIntegrationTests
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

        private static string FingerprintOf(string privateKeyPath)
        {
            var parts = File.ReadAllText(privateKeyPath + ".pub").Split(' ');
            return Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(parts[1])));
        }

        [IntegrationTestMethod]
        public async Task Rsa_public_key_authenticates()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var key = OpenSshClient.GenerateKeyPair(_tempDir, "rsa", 2048);
            server.AcceptedFingerprints.Add(FingerprintOf(key));

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, key)} -o BatchMode=yes " +
                $"-o PreferredAuthentications=publickey {OpenSshClient.Target(TestSshServer.Username)} \"echo rsa-authenticated\"",
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
            StringAssert.Contains(result.StandardOutput, "rsa-authenticated");
        }

        [IntegrationTestMethod]
        public async Task Unsupported_ed25519_key_is_rejected_without_breaking_the_server()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var unsupported = OpenSshClient.GenerateKeyPair(_tempDir, "ed25519");
            server.AcceptedFingerprints.Add("*");

            var rejected = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, unsupported)} -o BatchMode=yes " +
                $"-o PreferredAuthentications=publickey -o NumberOfPasswordPrompts=0 " +
                $"{OpenSshClient.Target(TestSshServer.Username)} exit 0",
                timeoutMs: 30_000);
            Assert.AreNotEqual(0, rejected.ExitCode, "an unsupported key type must not authenticate");

            // The failed publickey attempt must leave the connection/session
            // machinery healthy enough for a normal password login.
            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, TestSshServer.Password);
            var password = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password " +
                $"-o NumberOfPasswordPrompts=1 {OpenSshClient.Target(TestSshServer.Username)} \"echo still-alive\"",
                env,
                timeoutMs: 30_000);

            Assert.AreEqual(0, password.ExitCode, $"stderr: {password.StandardError}");
            StringAssert.Contains(password.StandardOutput, "still-alive");
        }

        [IntegrationTestMethod]
        public async Task Wrong_username_is_rejected()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, TestSshServer.Password);

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password " +
                $"-o NumberOfPasswordPrompts=1 intruder@127.0.0.1 \"echo should-not-run\"",
                env,
                timeoutMs: 30_000);

            Assert.AreNotEqual(0, result.ExitCode, "an unknown username must not authenticate");
            Assert.IsFalse(result.StandardOutput.Contains("should-not-run"));
        }

        [IntegrationTestMethod]
        public async Task Rejected_public_key_falls_back_to_password()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var rejectedKey = OpenSshClient.GenerateKeyPair(_tempDir); // never registered
            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, TestSshServer.Password);

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, rejectedKey)} " +
                $"-o PreferredAuthentications=publickey,password -o NumberOfPasswordPrompts=1 " +
                $"{OpenSshClient.Target(TestSshServer.Username)} \"echo fallback-ok\"",
                env,
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
            StringAssert.Contains(result.StandardOutput, "fallback-ok");
        }

        [IntegrationTestMethod]
        public async Task Repeated_password_failures_do_not_poison_a_later_login()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();

            for (var attempt = 0; attempt < 5; attempt++)
            {
                var wrongDir = _tempDir + $"-wrong-{attempt}";
                Directory.CreateDirectory(wrongDir);
                var (_, wrongEnv) = OpenSshClient.CreatePasswordAuthHelper(wrongDir, "wrong-" + attempt);
                try
                {
                    var wrong = OpenSshClient.Ssh(
                        $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password " +
                        $"-o NumberOfPasswordPrompts=1 {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                        wrongEnv,
                        timeoutMs: 30_000);
                    Assert.AreNotEqual(0, wrong.ExitCode);
                }
                finally
                {
                    try { Directory.Delete(_tempDir + $"-wrong-{attempt}", recursive: true); } catch { }
                }
            }

            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, TestSshServer.Password);
            var good = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password " +
                $"-o NumberOfPasswordPrompts=1 {OpenSshClient.Target(TestSshServer.Username)} \"echo recovered\"",
                env,
                timeoutMs: 30_000);

            Assert.AreEqual(0, good.ExitCode, $"stderr: {good.StandardError}");
            StringAssert.Contains(good.StandardOutput, "recovered");
        }
    }
}
