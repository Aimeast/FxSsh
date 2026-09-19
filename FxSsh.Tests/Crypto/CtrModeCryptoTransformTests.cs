using System;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Crypto
{
    [TestClass]
    public sealed class CtrModeCryptoTransformTests
    {
        private static CtrModeCryptoTransform CreateTransform(byte[] key, byte[] iv)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            return new CtrModeCryptoTransform(aes);
        }

        [TestMethod]
        public void Matches_NIST_SP_800_38A_AES_128_CTR_vectors()
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var counter = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var plaintext = Convert.FromHexString(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710");
            var expected = Convert.FromHexString(
                "874d6191b620e3261bef6864990db6ce" +
                "9806f66b7970fdff8617187bb9fffdff" +
                "5ae4df3edbd5d35e5b4f09020db03eab" +
                "1e031dda2fbe03d1792170a0f3009cee");

            using var transform = CreateTransform(key, counter);
            var output = new byte[plaintext.Length];

            var written = transform.TransformBlock(plaintext, 0, plaintext.Length, output, 0);

            CollectionAssert.AreEqual(expected, output);
            Assert.AreEqual(plaintext.Length, written);
        }

        [TestMethod]
        public void Encrypt_then_decrypt_restores_the_plaintext()
        {
            var key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
            var iv = Convert.FromHexString("101112131415161718191a1b1c1d1e1f");
            var plaintext = Convert.FromHexString("00112233445566778899aabbccddeeff");

            byte[] ciphertext;
            using (var encryptor = CreateTransform(key, iv))
            {
                ciphertext = new byte[plaintext.Length];
                encryptor.TransformBlock(plaintext, 0, plaintext.Length, ciphertext, 0);
            }

            using var decryptor = CreateTransform(key, iv);
            var output = new byte[ciphertext.Length];
            decryptor.TransformBlock(ciphertext, 0, ciphertext.Length, output, 0);

            CollectionAssert.AreEqual(plaintext, output);
        }

        [TestMethod]
        public void Counter_continues_across_calls()
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var plaintext = Convert.FromHexString(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef" +
                "f69f2445df4f9b17ad2b417be66c3710");

            // Two split calls on one transform...
            byte[] split;
            using (var transform = CreateTransform(key, iv))
            {
                split = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, 16, split, 0);
                transform.TransformBlock(plaintext, 16, plaintext.Length - 16, split, 16);
            }

            // ...must equal one combined call on a fresh transform.
            byte[] oneShot;
            using (var transform = CreateTransform(key, iv))
            {
                oneShot = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, plaintext.Length, oneShot, 0);
            }

            CollectionAssert.AreEqual(oneShot, split);
        }

        [TestMethod]
        public void Partial_call_advances_the_counter_by_whole_blocks()
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var plaintext = Convert.FromHexString(
                "6bc1bee22e409f96e93d7e117393172a" +
                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                "30c81c46a35ce411e5fbc1191a0a52ef");

            // Reference keystream: one-shot over 48 bytes = 3 counter blocks.
            byte[] reference;
            using (var transform = CreateTransform(key, iv))
            {
                reference = new byte[48];
                transform.TransformBlock(plaintext, 0, 48, reference, 0);
            }

            // A 20-byte call consumes two counter blocks but only 20 bytes of
            // keystream; the tail of block 1 is discarded and the next call
            // continues from block 2. Real SSH traffic always encrypts
            // block-aligned lengths, so this granularity is never visible.
            byte[] split;
            using (var transform = CreateTransform(key, iv))
            {
                split = new byte[36];
                transform.TransformBlock(plaintext, 0, 20, split, 0);
                transform.TransformBlock(plaintext, 20, 16, split, 20);
            }

            CollectionAssert.AreEqual(reference[..20], split[..20]);

            // The tail continues from counter block 2: derive the expected
            // bytes with a fresh transform positioned there via a 32-byte
            // warm-up call.
            byte[] expectedTail;
            using (var transform = CreateTransform(key, iv))
            {
                var warmUp = new byte[32];
                transform.TransformBlock(warmUp, 0, warmUp.Length, warmUp, 0);
                expectedTail = new byte[16];
                transform.TransformBlock(plaintext, 20, 16, expectedTail, 0);
            }

            CollectionAssert.AreEqual(expectedTail, split[20..36]);
        }

        [TestMethod]
        public void Counter_carries_into_higher_bytes()
        {
            // IV ends FE: three 16-byte blocks consume FE, FF and then wrap
            // 00 00 - a fresh one-shot transform over the same data must
            // produce the identical keystream.
            var key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
            var iv = new byte[16];
            Array.Fill(iv, (byte)0xFF);
            iv[15] = 0xFE;
            var plaintext = new byte[48];

            byte[] split;
            using (var transform = CreateTransform(key, (byte[])iv.Clone()))
            {
                split = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, 16, split, 0);
                transform.TransformBlock(plaintext, 16, 32, split, 16);
            }

            byte[] oneShot;
            using (var transform = CreateTransform(key, (byte[])iv.Clone()))
            {
                oneShot = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, plaintext.Length, oneShot, 0);
            }

            CollectionAssert.AreEqual(oneShot, split);
        }

        [TestMethod]
        public void Input_larger_than_the_keystream_buffer_uses_the_fallback_path()
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var plaintext = new byte[70_000]; // > 64 KiB keystream buffer
            Random.Shared.NextBytes(plaintext);

            // Cross the hot-path/fallback boundary mid-stream: small call,
            // huge call, then small again - the counter must stay consistent
            // with a fresh one-shot transform over the whole stream.
            byte[] split;
            using (var transform = CreateTransform(key, iv))
            {
                split = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, 32, split, 0);
                transform.TransformBlock(plaintext, 32, 69_936, split, 32);
                transform.TransformBlock(plaintext, 69_968, 32, split, 69_968);
            }

            byte[] oneShot;
            using (var transform = CreateTransform(key, iv))
            {
                oneShot = new byte[plaintext.Length];
                transform.TransformBlock(plaintext, 0, plaintext.Length, oneShot, 0);
            }

            CollectionAssert.AreEqual(oneShot, split);
        }

        [TestMethod]
        public void TransformFinalBlock_returns_xored_output()
        {
            var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
            var iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var plaintext = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");

            using var transform = CreateTransform(key, iv);
            var final = transform.TransformFinalBlock(plaintext, 0, plaintext.Length);
            var streaming = new byte[plaintext.Length];
            using var second = CreateTransform(key, iv);
            second.TransformBlock(plaintext, 0, plaintext.Length, streaming, 0);

            CollectionAssert.AreEqual(streaming, final);
        }

        [TestMethod]
        public void Transform_metadata_reports_aes_block_size()
        {
            using var transform = CreateTransform(
                Convert.FromHexString("000102030405060708090a0b0c0d0e0f"),
                Convert.FromHexString("101112131415161718191a1b1c1d1e1f"));

            Assert.IsTrue(transform.CanReuseTransform);
            Assert.IsTrue(transform.CanTransformMultipleBlocks);
            Assert.AreEqual(128, transform.InputBlockSize);
            Assert.AreEqual(128, transform.OutputBlockSize);
        }
    }
}
