using System;
using System.Linq;
using FxSsh.Algorithms.Catalog;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Catalog
{
    /// <summary>
    /// Verifies the seeded algorithm catalog: which algorithms ship enabled,
    /// which are disabled legacy fallbacks, and the preference order that
    /// drives SSH name-list negotiation.
    /// </summary>
    [TestClass]
    public sealed class AlgorithmCatalogTests
    {
        private readonly AlgorithmCatalog _catalog = new();

        [TestMethod]
        public void HostKey_seeds_five_algorithms_in_preference_order()
        {
            CollectionAssert.AreEqual(
                new[]
                {
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "ecdsa-sha2-nistp521",
                    "rsa-sha2-256",
                    "rsa-sha2-512",
                },
                _catalog.HostKeyCollection.NegotiableNames.ToArray());
        }

        [TestMethod]
        public void KeyExchange_prefers_hybrid_post_quantum_then_curve25519_then_ecdh_then_dh()
        {
            var names = _catalog.KeyExchangeCollection.NegotiableNames.ToArray();

            // Platform-conditional entries (mlkem, curve25519) may be absent,
            // but whatever survives must keep this relative order. The
            // diffie-hellman entries are unconditionally supported.
            var ordered = names.Where(n =>
                    n == "mlkem768x25519-sha256" ||
                    n == "curve25519-sha256" ||
                    n == "ecdh-sha2-nistp256" ||
                    n == "diffie-hellman-group14-sha256")
                .ToArray();

            CollectionAssert.AreEqual(
                new[] { "mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256" }
                    .Where(n => names.Contains(n))
                    .ToArray(),
                ordered);
            CollectionAssert.Contains(names, "diffie-hellman-group18-sha512");
            CollectionAssert.Contains(names, "diffie-hellman-group16-sha512");
        }

        [TestMethod]
        public void Encryption_seeds_modern_ciphers_and_disables_legacy_ones()
        {
            CollectionAssert.AreEqual(
                new[] { "aes256-ctr", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com" },
                _catalog.EncryptionCollection.NegotiableNames.ToArray());
        }

        [TestMethod]
        public void Hmac_seeds_etm_first_and_disables_sha1()
        {
            CollectionAssert.AreEqual(
                new[]
                {
                    "hmac-sha2-256-etm@openssh.com",
                    "hmac-sha2-512-etm@openssh.com",
                    "hmac-sha2-256",
                    "hmac-sha2-512",
                },
                _catalog.HmacCollection.NegotiableNames.ToArray());
        }

        [TestMethod]
        public void Compression_only_offers_none()
        {
            CollectionAssert.AreEqual(new[] { "none" }, _catalog.CompressionCollection.NegotiableNames.ToArray());
        }

        [TestMethod]
        public void Re_enabled_legacy_cipher_negotiates_at_the_tail()
        {
            // Enable() on a seeded-disabled entry re-activates it at its
            // original (tail) position: below every modern cipher.
            _catalog.EncryptionCollection.Enable("aes128-cbc");

            var names = _catalog.EncryptionCollection.NegotiableNames.ToArray();

            Assert.AreEqual("aes128-cbc", names[^1]);
            Assert.AreEqual("aes256-ctr", names[0]);
        }

        [TestMethod]
        public void Removing_entries_updates_negotiation()
        {
            _catalog.KeyExchangeCollection.Remove("diffie-hellman-group18-sha512");

            CollectionAssert.DoesNotContain(_catalog.KeyExchangeCollection.NegotiableNames.ToArray(), "diffie-hellman-group18-sha512");
        }

        [TestMethod]
        public void Clearing_a_collection_yields_an_empty_selection()
        {
            _catalog.HmacCollection.Clear();

            Assert.AreEqual(0, _catalog.HmacCollection.BuildCollection().Count);
        }

        [TestMethod]
        public void Every_negotiable_factory_constructs_an_instance()
        {
            // Invoking the factories with a null key is what the session does
            // (keys are imported later from wire data / host key PEMs).
            InvokeAllFactories(_catalog.HostKeyCollection, "hostkey");
            InvokeAllFactories(_catalog.KeyExchangeCollection, "kex");
            InvokeAllFactories(_catalog.EncryptionCollection, "cipher");
            InvokeAllFactories(_catalog.HmacCollection, "hmac");
            InvokeAllFactories(_catalog.CompressionCollection, "compression");
        }

        private static void InvokeAllFactories<T>(AlgorithmCollectionBuilder<T> builder, string category)
        {
            var frozen = builder.BuildCollection();
            Assert.IsTrue(frozen.Count > 0, $"{category} collection is empty");

            foreach (var name in frozen.Keys)
            {
                var factory = frozen[name];
                Assert.IsNotNull(factory(null), $"{category}/{name} factory returned null");
            }
        }
    }
}
