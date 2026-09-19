using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FxSsh.Algorithms.Catalog;
using FxSsh.IntegrationTests.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Integration
{
    /// <summary>
    /// Forces each enabled algorithm individually with a real OpenSSH client
    /// (the benchmark_report.md probing approach): KEX, encryption, MAC and
    /// the host key algorithms the fixture registers.
    /// </summary>
    [TestCategory("Integration")]
    [TestClass]
    public sealed class AlgorithmNegotiationIntegrationTests
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
        public async Task Every_enabled_algorithm_negotiates_with_a_real_client()
        {
            IntegrationGuard.RequireSshClient();
            await using var server = await TestSshServer.StartAsync(allowNoneAuth: true);

            // Probe every algorithm the library enables. The CI Windows job
            // installs the latest Win32-OpenSSH, whose client knows the full
            // catalog (mlkem768x25519-sha256 needs a 9.9+ client); a client
            // that cannot name an algorithm fails loudly instead of being
            // silently skipped.
            var catalog = new AlgorithmCatalog();
            var kexAlgorithms = catalog.KeyExchangeCollection.NegotiableNames.ToArray();
            var ciphers = catalog.EncryptionCollection.NegotiableNames.ToArray();
            var macs = catalog.HmacCollection.NegotiableNames.ToArray();
            // Only algorithms the fixture has host keys for.
            var hostKeys = new[] { "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512" };

            var failures = new List<string>();
            var checks = 0;

            void Probe(string optionName, string value)
            {
                var result = OpenSshClient.Ssh(
                    $"{OpenSshClient.CommonOptions(server.Port)} -o BatchMode=yes -o PreferredAuthentications=none {optionName}={value} {OpenSshClient.Target(TestSshServer.Username)} \"exit 0\"",
                    timeoutMs: 60_000);

                if (result.ExitCode != 0)
                    failures.Add($"{optionName}={value}: exit {result.ExitCode}, stderr: {result.StandardError.Trim()}");
                checks++;
            }

            foreach (var kex in kexAlgorithms)
                Probe("-o KexAlgorithms", kex);

            foreach (var cipher in ciphers)
                Probe("-o Ciphers", cipher);

            foreach (var mac in macs)
                Probe("-o MACs", mac);

            foreach (var hostKey in hostKeys)
                Probe("-o HostKeyAlgorithms", hostKey);

            Assert.AreEqual(0, failures.Count, $"failed negotiations ({checks} probed):\n{string.Join("\n", failures)}");
        }
    }
}
