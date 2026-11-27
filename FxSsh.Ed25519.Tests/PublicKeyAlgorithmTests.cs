using System;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace FxSsh.Tests.Keys
{
    [TestClass]
    public sealed class Ed25519PublicKeyAlgorithmTests
    {
        private static string NewEd25519Pem() => KeyGenerator.GenerateEd25519KeyPem();
        
        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.RsaKey_names_follow_the_signature_hash"/>
        /// </summary>
        [TestMethod]
        public void Ed25519Key_names_follow_the_signature_hash()
        {
            var pem = NewEd25519Pem();

            Assert.AreEqual("ssh-ed25519", new Ed25519Key(pem).Name);
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.RsaKey_signature_round_trip_and_tamper_detection"/>
        /// </summary>
        [TestMethod]
        public void RsaKey_signature_round_trip_and_tamper_detection()
        {
            var key = new Ed25519Key(NewEd25519Pem());
            var data = Encoding.ASCII.GetBytes("authenticate me");

            var signature = key.SignData(data);
            Assert.IsTrue(key.VerifyData(data, signature));
            Assert.IsFalse(key.VerifyData(Encoding.ASCII.GetBytes("authenticate me!"), signature));

            var hash = SHA512.HashData(data);
            var hashSignature = key.SignHash(hash);
            Assert.IsTrue(key.VerifyHash(hash, hashSignature));
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.RsaKey_rejects_foreign_key_blobs"/>
        /// </summary>
        [TestMethod]
        public void Ed25519Key_rejects_foreign_key_blobs()
        {
            var key = new Ed25519Key(NewEd25519Pem());

            // A well-formed blob naming another algorithm is refused.
            var wrongName = new SshDataWriter().Write("ssh-dss", Encoding.ASCII).ToByteArray();
            Assert.ThrowsExactly<CryptographicException>(() => key.LoadKeyAndCertificatesData(wrongName));

            // Tiny garbage fails while reading the name-list length prefix.
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => key.LoadKeyAndCertificatesData(new byte[] { 0x00, 0x01, 0x02 }));
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.RsaKey_key_blob_round_trips_and_fingerprints_are_stable"/>
        /// </summary>
        [TestMethod]
        public void RsaKey_key_blob_round_trips_and_fingerprints_are_stable()
        {
            var pem = NewEd25519Pem();
            var first = new Ed25519Key(pem);
            var second = new Ed25519Key(first.ExportKey());

            var blob = first.CreateKeyAndCertificatesData();
            second.LoadKeyAndCertificatesData(blob);

            CollectionAssert.AreEqual(blob, second.CreateKeyAndCertificatesData());
            Assert.AreEqual(first.GetFingerprint(), second.GetFingerprint());
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.Signature_data_carries_the_algorithm_name"/>
        /// </summary>
        [TestMethod]
        public void Signature_data_carries_the_algorithm_name()
        {
            var key = new Ed25519Key(NewEd25519Pem());
            var signatureData = key.CreateSignatureData(Encoding.ASCII.GetBytes("data"));

            // GetSignature unwraps the SSH signature blob (name || signature).
            var signature = key.GetSignature(signatureData);
            Assert.IsTrue(key.VerifyData(Encoding.ASCII.GetBytes("data"), signature));

            // // A blob naming a different algorithm is rejected.
            // var key2 = new Ed25519Key(NewEd25519Pem());
            // Assert.ThrowsExactly<CryptographicException>(
            //     () => key.GetSignature(new Ed25519Key(key2.ExportKey()).CreateSignatureData(Encoding.ASCII.GetBytes("data"))));
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.EcdsaKey_generates_and_round_trips_on_every_curve"/>
        /// </summary>
        [TestMethod]
        public void Ed25519Key_generates_and_round_trips_on_every_curve()
        {
            // An empty key makes the constructor generate a fresh key.
            var key = new Ed25519Key(string.Empty);
            Assert.AreEqual($"ssh-ed25519", key.Name);

            var imported = new Ed25519Key(key.ExportKey());
            var blob = key.CreateKeyAndCertificatesData();
            imported.LoadKeyAndCertificatesData(blob);

            CollectionAssert.AreEqual(blob,
                imported.CreateKeyAndCertificatesData(), $"Ed25519 (no params)");
            Assert.AreEqual(key.GetFingerprint(), imported.GetFingerprint());
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.EcdsaKey_signature_round_trip_in_ssh_blob_format"/>
        /// </summary>
        [TestMethod]
        public void Ed25519Key_signature_round_trip_in_ssh_blob_format()
        {
            // SignData emits the SSH (r,s) mpint blob; VerifyData converts it
            // back to IEEE P1363 - the pair exercises both conversions.
            var key = new Ed25519Key(NewEd25519Pem());
            var data = Encoding.ASCII.GetBytes("ssh signature payload");

            var signature = key.SignData(data);
            Assert.IsTrue(key.VerifyData(data, signature));
            Assert.IsFalse(key.VerifyData(Encoding.ASCII.GetBytes("other"), signature));

            var hash = SHA256.HashData(data);
            var hashSignature = key.SignHash(hash);
            Assert.IsTrue(key.VerifyHash(hash, hashSignature));
        }

        /// <summary>
        /// Adapted from:
        /// <see cref="PublicKeyAlgorithmTests.RsaKey_fingerprints_differ_between_keys"/>
        /// <see cref="PublicKeyAlgorithmTests.EcdsaKey_fingerprints_differ_between_keys"/>
        /// </summary>
        [TestMethod]
        public void Ed25519Key_fingerprints_differ_between_keys()
        {
            var a = new Ed25519Key(string.Empty).GetFingerprint();
            var b = new Ed25519Key(string.Empty).GetFingerprint();

            Assert.AreNotEqual(a, b);
        }
    }

    [TestClass]
    public sealed class Ed25519KeyGeneratorTests
    {
        /// <summary>
        /// Adapted from:
        /// <see cref="KeyGeneratorTests.Generated_rsa_pem_imports_into_RsaKey"/>
        /// <see cref="KeyGeneratorTests.Generated_ecdsa_pem_imports_into_EcdsaKey"/>
        /// </summary>
        [TestMethod]
        public void Generated_ed25519_pem_imports_into_Ed25519Key()
        {
            var pem = KeyGenerator.GenerateEd25519KeyPem();

            StringAssert.Contains(pem, "BEGIN PRIVATE KEY");
            var key = new Ed25519Key(pem);
            Assert.IsFalse(string.IsNullOrEmpty(key.GetFingerprint()));
        }
    }
}
