using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AuthIntegrationTests
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
        public async Task Password_auth_accepts_the_correct_password()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, TestSshServer.Password);

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                env,
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
        }

        [IntegrationTestMethod]
        public async Task Password_auth_rejects_a_wrong_password()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var (_, env) = OpenSshClient.CreatePasswordAuthHelper(_tempDir, "totally-wrong");

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                env,
                timeoutMs: 30_000);

            Assert.AreNotEqual(0, result.ExitCode, "authentication must fail");
        }

        [IntegrationTestMethod]
        public async Task PublicKey_auth_accepts_the_authorized_key()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var keyPath = OpenSshClient.GenerateKeyPair(_tempDir);
            server.AcceptedFingerprints.Add(FingerprintOf(keyPath));

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, keyPath)} -o BatchMode=yes {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
        }

        [IntegrationTestMethod]
        public async Task PublicKey_auth_rejects_an_unauthorized_key()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();
            var keyPath = OpenSshClient.GenerateKeyPair(_tempDir); // not registered

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port, keyPath)} -o BatchMode=yes -o NumberOfPasswordPrompts=0 {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                timeoutMs: 30_000);

            Assert.AreNotEqual(0, result.ExitCode, "authentication must fail");
        }

        [IntegrationTestMethod]
        public async Task None_auth_is_rejected_unless_enabled()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync();

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o BatchMode=yes -o PreferredAuthentications=none {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                timeoutMs: 30_000);

            Assert.AreNotEqual(0, result.ExitCode, "none auth must be rejected by default");
        }

        [IntegrationTestMethod]
        public async Task None_auth_works_when_enabled()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync(allowNoneAuth: true);

            var result = OpenSshClient.Ssh(
                $"{OpenSshClient.CommonOptions(server.Port)} -o BatchMode=yes -o PreferredAuthentications=none {OpenSshClient.Target(TestSshServer.Username)} exit 0",
                timeoutMs: 30_000);

            Assert.AreEqual(0, result.ExitCode, $"stderr: {result.StandardError}");
        }

        /// <summary>
        /// Compute the fingerprint of a generated key the way FxSsh reports
        /// it in <see cref="FxSsh.Services.UserAuthArgs.Fingerprint"/>: plain
        /// base64 (with padding) of the SHA-256 of the key blob.
        /// </summary>
        private static string FingerprintOf(string privateKeyPath)
        {
            var pub = File.ReadAllText(privateKeyPath + ".pub").Split(' ');
            var blob = Convert.FromBase64String(pub[1]);
            var hash = SHA256.HashData(blob);

            return Convert.ToBase64String(hash);
        }
    }
}
