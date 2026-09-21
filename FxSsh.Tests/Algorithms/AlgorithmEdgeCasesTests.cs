using System;
using System.Security.Cryptography;
using System.Text;
using FxSsh.Algorithms;
using FxSsh.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Algorithms
{
    /// <summary>
    /// Small algorithm-surface classes that complete the catalog coverage:
    /// the only built-in compression, the plugin HmacInfo constructor, the
    /// legacy 3DES cipher and the message documentation attribute.
    /// </summary>
    [TestClass]
    public sealed class AlgorithmEdgeCasesTests
    {
        [TestMethod]
        public void NoCompression_is_an_identity_round_trip()
        {
            var compression = new NoCompression();
            Assert.IsTrue(compression.IsIdentity);

            var payload = new byte[] { 0x01, 0x02, 0x03 };
            CollectionAssert.AreEqual(payload, compression.Compress(payload));
            CollectionAssert.AreEqual(payload, compression.Decompress(payload).ToArray());
        }

        [TestMethod]
        public void HmacInfo_plugin_constructor_builds_a_custom_mac()
        {
            const int keyBytes = 32;
            var info = new HmacInfo(key => new HmacAlgorithm(new HMACSHA256(key), 256, key), 256, isEtm: true);

            Assert.IsTrue(info.IsEtm);
            var mac = info.Hmac(new byte[keyBytes]);

            Assert.AreEqual(32, mac.DigestLength);
        }

        [TestMethod]
        public void HmacInfo_standard_constructor_reports_non_etm()
        {
            var info = new HmacInfo(new HMACSHA256(), 256);

            Assert.IsFalse(info.IsEtm);
        }

        [TestMethod]
        public void Legacy_3des_cipher_round_trips()
        {
            var info = new CipherInfo(System.Security.Cryptography.TripleDES.Create(), 192, CipherModeEx.CBC);
            Assert.AreEqual(192, info.KeySize);
            Assert.AreEqual(8, info.IVSize);

            var key = new byte[24];
            Random.Shared.NextBytes(key);
            var iv = new byte[8];
            Random.Shared.NextBytes(iv);

            var plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
            var cipher = info.Cipher(key, iv, true);
            var decipher = info.Cipher(key, iv, false);

            var ciphertext = cipher.Transform(plaintext);
            CollectionAssert.AreEqual(plaintext, decipher.Transform(ciphertext));
        }

        [TestMethod]
        public void MessageAttribute_carries_documentation_metadata()
        {
            var attribute = new MessageAttribute("SSH_MSG_DISCONNECT", 1);

            Assert.AreEqual("SSH_MSG_DISCONNECT", attribute.Name);
            Assert.AreEqual((byte)1, attribute.Number);
        }
    }
}
