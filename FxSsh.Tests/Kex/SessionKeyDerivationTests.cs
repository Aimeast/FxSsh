using System;
using System.Linq;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Kex
{
    /// <summary>
    /// RFC 4253 section 7.2 session key derivation. A short-hash KEX forces
    /// the derivation past its second hash block, which is where the
    /// concatenation of every previous block matters.
    /// </summary>
    [TestClass]
    public sealed class SessionKeyDerivationTests
    {
        private sealed class Sha1Kex : KexAlgorithm
        {
            public Sha1Kex()
            {
                _hashAlgorithm = SHA1.Create();
            }

            public override byte[] CreateKeyExchange() => [];

            public override byte[] DecryptKeyExchange(byte[] exchangeData) => [];
        }

        private static byte[] HashInput(KexAlgorithm kex, byte[] k, byte[] h, byte[] tail, byte[]? extra = null)
        {
            using var writer = new SshDataWriter();
            writer.WriteMpint(k);
            writer.WriteBytes(h);
            writer.WriteBytes(tail);
            if (extra != null)
                writer.WriteBytes(extra);
            return kex.ComputeHash(writer.ToByteArray());
        }

        [TestMethod]
        public void DeriveKey_follows_the_rfc4253_hash_chain_beyond_two_blocks()
        {
            var kex = new Sha1Kex();
            var sharedSecret = new byte[] { 0x01, 0x02, 0x03 };
            var exchangeHash = Enumerable.Range(1, 20).Select(i => (byte)i).ToArray();
            var sessionId = Enumerable.Range(101, 20).Select(i => (byte)i).ToArray();

            var derived = Session.DeriveKey(kex, exchangeHash, 50, sharedSecret, 'A', sessionId);

            var k1 = HashInput(kex, sharedSecret, exchangeHash, [(byte)'A'], sessionId);
            var k2 = HashInput(kex, sharedSecret, exchangeHash, k1);
            var k3 = HashInput(kex, sharedSecret, exchangeHash, [.. k1, .. k2]);

            var expected = k1.Concat(k2).Concat(k3.Take(10)).ToArray();
            CollectionAssert.AreEqual(expected, derived);
        }

        [TestMethod]
        public void DeriveKey_uses_the_session_id_only_in_the_first_block()
        {
            var kex = new Sha1Kex();
            var sharedSecret = new byte[] { 0x7f };
            var exchangeHash = Enumerable.Repeat((byte)0x11, 20).ToArray();
            var sessionId = Enumerable.Repeat((byte)0x22, 20).ToArray();

            var derived = Session.DeriveKey(kex, exchangeHash, 25, sharedSecret, 'C', sessionId);

            var k1 = HashInput(kex, sharedSecret, exchangeHash, [(byte)'C'], sessionId);
            var k2 = HashInput(kex, sharedSecret, exchangeHash, k1);

            CollectionAssert.AreEqual(k1.Concat(k2.Take(5)).ToArray(), derived);
        }
    }
}
