using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Kex
{
    [TestClass]
    public sealed class KexAlgorithmTests
    {
        private static void AssertAgreement(KexAlgorithm client, KexAlgorithm server)
        {
            var clientPublic = client.CreateKeyExchange();
            var serverShared = server.DecryptKeyExchange(clientPublic);
            var serverPublic = server.CreateKeyExchange();
            var clientShared = client.DecryptKeyExchange(serverPublic);

            CollectionAssert.AreEqual(serverShared, clientShared);
        }

        [TestMethod]
        public void DiffieHellman_group14_reaches_the_same_shared_secret()
        {
            AssertAgreement(new DiffieHellmanKex(256, 2048), new DiffieHellmanKex(256, 2048));
        }

        [TestMethod]
        public void DiffieHellman_group16_reaches_the_same_shared_secret()
        {
            AssertAgreement(new DiffieHellmanKex(512, 4096), new DiffieHellmanKex(512, 4096));
        }

        [TestMethod]
        public void DiffieHellman_rejects_unsupported_parameters()
        {
            Assert.ThrowsExactly<ArgumentException>(() => new DiffieHellmanKex(128, 2048));
            Assert.ThrowsExactly<ArgumentException>(() => new DiffieHellmanKex(256, 1024));
        }

        [TestMethod]
        public void Ecdh_agrees_on_every_supported_curve()
        {
            foreach (var curve in new[] { "nistp256", "nistp384", "nistp521" })
            {
                var client = new EcdhKex(curve);
                var server = new EcdhKex(curve);

                var clientPublic = client.CreateKeyExchange();
                var serverShared = server.DecryptKeyExchange(clientPublic);
                var serverPublic = server.CreateKeyExchange();
                var clientShared = client.DecryptKeyExchange(serverPublic);

                CollectionAssert.AreEqual(serverShared, clientShared, $"curve {curve}");
            }
        }

        [TestMethod]
        public void Ecdh_rejects_unknown_curves_and_malformed_points()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new EcdhKex("curve25519"));

            var server = new EcdhKex("nistp256");
            Assert.ThrowsExactly<InvalidDataException>(() => server.DecryptKeyExchange(new byte[] { 0x03, 0x01, 0x02 }));
            // Empty input fails while reading the point prefix.
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => server.DecryptKeyExchange(Array.Empty<byte>()));
        }

        [TestMethod]
        public void X25519_agrees_on_the_shared_secret()
        {
            var client = new X25519Kex();
            var server = new X25519Kex();

            var clientPublic = client.CreateKeyExchange();
            Assert.AreEqual(32, clientPublic.Length);

            var serverShared = server.DecryptKeyExchange(clientPublic);
            var serverPublic = server.CreateKeyExchange();
            Assert.AreEqual(32, serverPublic.Length);
            var clientShared = client.DecryptKeyExchange(serverPublic);

            CollectionAssert.AreEqual(serverShared, clientShared);
        }

        [TestMethod]
        public void X25519_validates_public_key_length_and_low_order_points()
        {
            var server = new X25519Kex();

            Assert.ThrowsExactly<InvalidDataException>(() => server.DecryptKeyExchange(new byte[31]));
            // An all-zero public key is a low-order point (RFC 7748 6.1):
            // Windows returns an all-zero secret which the check below
            // rejects; OpenSSL fails the derivation outright with its own
            // CryptographicException subclass. Both abort the exchange.
            Assert.Throws<CryptographicException>(() => server.DecryptKeyExchange(new byte[32]));
        }

        [TestMethod]
        public void MlkemX25519_full_exchange_agrees_on_the_shared_secret()
        {
            if (!MLKem.IsSupported)
            {
                Assert.Inconclusive("ML-KEM is not supported on this platform.");
            }

            // Client side: ML-KEM-768 encapsulation key || X25519 public key.
            using var clientKem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
            using var clientX = X25519DiffieHellman.GenerateKey();
            var encapsulationKey = clientKem.ExportEncapsulationKey();
            Assert.AreEqual(1184, encapsulationKey.Length);

            var cInit = new byte[encapsulationKey.Length + 32];
            encapsulationKey.CopyTo(cInit, 0);
            clientX.ExportPublicKey().CopyTo(cInit, encapsulationKey.Length);

            var server = new MlkemX25519Kex();
            Assert.IsTrue(server.SharedSecretIsString);

            var serverShared = server.DecryptKeyExchange(cInit);
            var sReply = server.CreateKeyExchange();

            // Server reply = 1088-byte KEM ciphertext || 32-byte X25519 key.
            Assert.AreEqual(1088 + 32, sReply.Length);

            var kPq = clientKem.Decapsulate(sReply.AsSpan(0, 1088).ToArray());
            var kCl = clientX.DeriveRawSecretAgreement(sReply.AsSpan(1088).ToArray());
            var clientShared = SHA256.HashData(kPq.AsSpan().ToArray().Concat(kCl).ToArray());

            CollectionAssert.AreEqual(clientShared, serverShared);
        }

        [TestMethod]
        public void MlkemX25519_enforces_state_and_length_validation()
        {
            if (!MLKem.IsSupported)
            {
                Assert.Inconclusive("ML-KEM is not supported on this platform.");
            }

            var server = new MlkemX25519Kex();

            // CreateKeyExchange before DecryptKeyExchange is a protocol error.
            Assert.ThrowsExactly<InvalidOperationException>(() => server.CreateKeyExchange());

            // Wrong C_INIT length fails before any KEM work.
            Assert.ThrowsExactly<InvalidDataException>(() => server.DecryptKeyExchange(new byte[1184 + 31]));

            // A failed exchange leaves the state machine untouched.
            Assert.ThrowsExactly<InvalidOperationException>(() => server.CreateKeyExchange());

            Assert.ThrowsExactly<ArgumentNullException>(() => server.DecryptKeyExchange(null!));
        }

        [TestMethod]
        public void ComputeHash_uses_the_negotiated_hash_algorithm()
        {
            var input = Encoding.ASCII.GetBytes("exchange hash input");

            CollectionAssert.AreEqual(SHA256.HashData(input), new X25519Kex().ComputeHash(input));
            CollectionAssert.AreEqual(SHA256.HashData(input), new EcdhKex("nistp256").ComputeHash(input));
        }
    }
}
