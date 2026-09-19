using System;
using System.Security.Cryptography;
using System.Text;
using FxSsh;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Keys
{
    [TestClass]
    public sealed class PublicKeyAlgorithmTests
    {
        private static string NewRsaPem() => KeyGenerator.GenerateRsaKeyPem(2048);

        private static string NewEcdsaPem(string curve) => KeyGenerator.GenerateECDsaKeyPem(curve);

        [TestMethod]
        public void RsaKey_names_follow_the_signature_hash()
        {
            var pem = NewRsaPem();

            Assert.AreEqual("rsa-sha2-256", new RsaKey(256, pem).Name);
            Assert.AreEqual("rsa-sha2-512", new RsaKey(512, pem).Name);

            // The wire key blob name stays "ssh-rsa" regardless of the
            // signature algorithm (RFC 8332 section 3).
            Assert.AreEqual("ssh-rsa", new RsaKey(256, pem).PublicKeyName);

            Assert.ThrowsExactly<ArgumentException>(() => new RsaKey(128, pem));
        }

        [TestMethod]
        public void RsaKey_signature_round_trip_and_tamper_detection()
        {
            var key = new RsaKey(512, NewRsaPem());
            var data = Encoding.ASCII.GetBytes("authenticate me");

            var signature = key.SignData(data);
            Assert.IsTrue(key.VerifyData(data, signature));
            Assert.IsFalse(key.VerifyData(Encoding.ASCII.GetBytes("authenticate me!"), signature));

            var hash = SHA512.HashData(data);
            var hashSignature = key.SignHash(hash);
            Assert.IsTrue(key.VerifyHash(hash, hashSignature));
        }

        [TestMethod]
        public void RsaKey_key_blob_round_trips_and_fingerprints_are_stable()
        {
            var pem = NewRsaPem();
            var first = new RsaKey(256, pem);
            var second = new RsaKey(512, first.ExportKey());

            var blob = first.CreateKeyAndCertificatesData();
            second.LoadKeyAndCertificatesData(blob);

            CollectionAssert.AreEqual(blob, second.CreateKeyAndCertificatesData());
            Assert.AreEqual(first.GetFingerprint(), second.GetFingerprint());
        }

        [TestMethod]
        public void RsaKey_rejects_foreign_key_blobs()
        {
            var key = new RsaKey(256, NewRsaPem());

            // A well-formed blob naming another algorithm is refused.
            var wrongName = new SshDataWriter().Write("ssh-dss", Encoding.ASCII).ToByteArray();
            Assert.ThrowsExactly<CryptographicException>(() => key.LoadKeyAndCertificatesData(wrongName));

            // Tiny garbage fails while reading the name-list length prefix.
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => key.LoadKeyAndCertificatesData(new byte[] { 0x00, 0x01, 0x02 }));
        }

        [TestMethod]
        public void Signature_data_carries_the_algorithm_name()
        {
            var key = new RsaKey(256, NewRsaPem());
            var signatureData = key.CreateSignatureData(Encoding.ASCII.GetBytes("data"));

            // GetSignature unwraps the SSH signature blob (name || signature).
            var signature = key.GetSignature(signatureData);
            Assert.IsTrue(key.VerifyData(Encoding.ASCII.GetBytes("data"), signature));

            // A blob naming a different algorithm is rejected.
            Assert.ThrowsExactly<CryptographicException>(
                () => key.GetSignature(new RsaKey(512, key.ExportKey()).CreateSignatureData(Encoding.ASCII.GetBytes("data"))));
        }

        [TestMethod]
        public void RsaKey_fingerprints_differ_between_keys()
        {
            var a = new RsaKey(256, NewRsaPem()).GetFingerprint();
            var b = new RsaKey(256, NewRsaPem()).GetFingerprint();

            Assert.AreNotEqual(a, b);
        }

        [TestMethod]
        public void EcdsaKey_generates_and_round_trips_on_every_curve()
        {
            foreach (var curve in new[] { "nistp256", "nistp384", "nistp521" })
            {
                // An empty key makes the constructor generate a fresh key.
                var key = new EcdsaKey(curve, string.Empty);
                Assert.AreEqual($"ecdsa-sha2-{curve}", key.Name);

                var imported = new EcdsaKey(curve, key.ExportKey());
                var blob = key.CreateKeyAndCertificatesData();
                imported.LoadKeyAndCertificatesData(blob);

                CollectionAssert.AreEqual(blob, imported.CreateKeyAndCertificatesData(), $"curve {curve}");
                Assert.AreEqual(key.GetFingerprint(), imported.GetFingerprint());
            }
        }

        [TestMethod]
        public void EcdsaKey_signature_round_trip_in_ssh_blob_format()
        {
            // SignData emits the SSH (r,s) mpint blob; VerifyData converts it
            // back to IEEE P1363 - the pair exercises both conversions.
            var key = new EcdsaKey("nistp256", NewEcdsaPem("nistp256"));
            var data = Encoding.ASCII.GetBytes("ssh signature payload");

            var signature = key.SignData(data);
            Assert.IsTrue(key.VerifyData(data, signature));
            Assert.IsFalse(key.VerifyData(Encoding.ASCII.GetBytes("other"), signature));

            var hash = SHA256.HashData(data);
            var hashSignature = key.SignHash(hash);
            Assert.IsTrue(key.VerifyHash(hash, hashSignature));
        }

        [TestMethod]
        public void EcdsaKey_rejects_unknown_curves()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new EcdsaKey("curve25519", string.Empty));
        }

        [TestMethod]
        public void EcdsaKey_rejects_compressed_curve_points()
        {
            var key = new EcdsaKey("nistp256", NewEcdsaPem("nistp256"));

            // Blob prefix must be the algorithm name; a valid name but a
            // compressed point (0x02) is rejected inside LoadKeyAndCertificatesData.
            var blob = new SshDataWriter()
                .Write(key.Name, Encoding.ASCII)
                .Write("nistp256", Encoding.ASCII)
                .WriteBinary(new byte[] { 0x02 })
                .ToByteArray();

            Assert.ThrowsExactly<CryptographicException>(() => key.LoadKeyAndCertificatesData(blob));
        }

        [TestMethod]
        public void EcdsaKey_fingerprints_differ_between_keys()
        {
            var a = new EcdsaKey("nistp256", string.Empty).GetFingerprint();
            var b = new EcdsaKey("nistp256", string.Empty).GetFingerprint();

            Assert.AreNotEqual(a, b);
        }
    }

    [TestClass]
    public sealed class KeyGeneratorTests
    {
        [TestMethod]
        public void Generated_rsa_pem_imports_into_RsaKey()
        {
            var pem = KeyGenerator.GenerateRsaKeyPem(2048);

            StringAssert.Contains(pem, "BEGIN PRIVATE KEY");
            var key = new RsaKey(256, pem);
            Assert.IsFalse(string.IsNullOrEmpty(key.GetFingerprint()));
        }

        [TestMethod]
        public void Generated_ecdsa_pem_imports_into_EcdsaKey()
        {
            foreach (var curve in new[] { "nistp256", "nistp384", "nistp521" })
            {
                var pem = KeyGenerator.GenerateECDsaKeyPem(curve);

                StringAssert.Contains(pem, "BEGIN PRIVATE KEY");
                var key = new EcdsaKey(curve, pem);
                Assert.IsFalse(string.IsNullOrEmpty(key.GetFingerprint()));
            }
        }

        [TestMethod]
        public void Key_generation_validates_arguments()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KeyGenerator.GenerateRsaKeyPem(1024));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KeyGenerator.GenerateECDsaKeyPem("curve25519"));
            Assert.ThrowsExactly<ArgumentNullException>(() => KeyGenerator.ConvertRsaBase64KeyToPem(null!));
        }

        [TestMethod]
        public void Legacy_csp_blob_converts_to_pkcs8_pem()
        {
            // Produce a legacy CSP blob the way old FxSsh host keys were stored.
            using var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
            var cspBlob = Convert.ToBase64String(rsa.ExportCspBlob(includePrivateParameters: true));

            var pem = KeyGenerator.ConvertRsaBase64KeyToPem(cspBlob);

            StringAssert.Contains(pem, "BEGIN PRIVATE KEY");
            var key = new RsaKey(512, pem);
            Assert.IsFalse(string.IsNullOrEmpty(key.GetFingerprint()));
        }
    }
}
