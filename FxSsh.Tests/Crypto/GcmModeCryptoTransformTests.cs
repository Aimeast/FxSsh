using System;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Crypto
{
    [TestClass]
    public sealed class GcmModeCryptoTransformTests
    {
        private static readonly byte[] Key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        private static byte[] MakeFrame(byte[] packetLengthBytes, byte[] body)
        {
            var frame = new byte[4 + body.Length];
            packetLengthBytes.CopyTo(frame, 0);
            body.CopyTo(frame, 4);
            return frame;
        }

        private static byte[] IncrementLastEight(byte[] iv)
        {
            var counter = iv[4..];
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }

            var nonce = new byte[12];
            iv[..4].CopyTo(nonce, 0);
            counter.CopyTo(nonce, 4);
            return nonce;
        }

        [TestMethod]
        public void First_packet_uses_the_iv_as_nonce_verbatim()
        {
            var iv = Convert.FromHexString("00112233445566778899aabb");
            var frame = MakeFrame(
                Convert.FromHexString("00000014"),
                Convert.FromHexString("00112233445566778899aabbccddeeff00112233"));

            var transform = new GcmModeCryptoTransform(Key, iv);
            var actual = new byte[frame.Length + 16];
            transform.Encrypt(0, frame, actual);

            // RFC 5647 7.1 + OpenSSL SET_IV_FIXED(arg=-1): the first packet's
            // invocation counter is the IV's last 8 bytes verbatim, so the
            // nonce equals the whole IV.
            using var reference = new AesGcm(Key, 16);
            var expected = new byte[frame.Length + 16];
            frame[..4].CopyTo(expected, 0);
            reference.Encrypt(
                iv,
                frame[4..],
                expected.AsSpan(4, frame.Length - 4),
                expected.AsSpan(frame.Length),
                frame[..4]);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Invocation_counter_advances_big_endian_per_packet()
        {
            var iv = Convert.FromHexString("00112233445566778899aabb");
            var frame = MakeFrame(
                Convert.FromHexString("00000014"),
                Convert.FromHexString("00112233445566778899aabbccddeeff00112233"));

            var transform = new GcmModeCryptoTransform(Key, iv);
            var first = new byte[frame.Length + 16];
            var second = new byte[frame.Length + 16];
            transform.Encrypt(0, frame, first);
            transform.Encrypt(1, frame, second);

            // The sequence number is not used by RFC 5647; the nonce advances
            // once per packet instead. Two packets therefore differ.
            CollectionAssert.AreNotEqual(first, second);

            using var reference = new AesGcm(Key, 16);
            var expectedSecond = new byte[frame.Length + 16];
            frame[..4].CopyTo(expectedSecond, 0);
            var nonce1 = IncrementLastEight(iv);
            reference.Encrypt(
                nonce1,
                frame[4..],
                expectedSecond.AsSpan(4, frame.Length - 4),
                expectedSecond.AsSpan(frame.Length),
                frame[..4]);

            CollectionAssert.AreEqual(expectedSecond, second);
        }

        [TestMethod]
        public void Decrypt_restores_the_frame_body()
        {
            var iv = Convert.FromHexString("00112233445566778899aabb");
            var body = Convert.FromHexString("00112233445566778899aabbccddeeff00112233");
            var frame = MakeFrame(Convert.FromHexString("00000014"), body);

            // Session creates one EncryptionAlgorithm per direction, each with
            // its own invocation counter - mirror that here.
            var encryptor = new GcmModeCryptoTransform(Key, iv);
            var decryptor = new GcmModeCryptoTransform(Key, iv);
            var wire = new byte[frame.Length + 16];
            encryptor.Encrypt(0, frame, wire);

            Assert.AreEqual(0x14, decryptor.DecryptPacketLength(0, wire.AsSpan(0, 4)));

            var plaintext = new byte[body.Length];
            decryptor.Decrypt(0, wire.AsSpan(0, 4), wire.AsSpan(4), plaintext);

            CollectionAssert.AreEqual(body, plaintext);
        }

        [TestMethod]
        public void Decrypt_rejects_tampered_ciphertext()
        {
            var iv = Convert.FromHexString("00112233445566778899aabb");
            var body = new byte[20];
            var frame = MakeFrame(Convert.FromHexString("00000014"), body);

            var encryptor = new GcmModeCryptoTransform(Key, iv);
            var decryptor = new GcmModeCryptoTransform(Key, iv);
            var wire = new byte[frame.Length + 16];
            encryptor.Encrypt(0, frame, wire);
            wire[5] ^= 0xFF;

            var plaintext = new byte[body.Length];
            Assert.ThrowsExactly<AuthenticationTagMismatchException>(
                () => decryptor.Decrypt(0, wire.AsSpan(0, 4), wire.AsSpan(4), plaintext));
        }

        [TestMethod]
        public void Decrypt_rejects_tampered_length_field()
        {
            var iv = Convert.FromHexString("00112233445566778899aabb");
            var body = new byte[20];
            var frame = MakeFrame(Convert.FromHexString("00000014"), body);

            var encryptor = new GcmModeCryptoTransform(Key, iv);
            var decryptor = new GcmModeCryptoTransform(Key, iv);
            var wire = new byte[frame.Length + 16];
            encryptor.Encrypt(0, frame, wire);
            wire[0] ^= 0xFF; // The length field is the AAD: tampering breaks the tag.

            var plaintext = new byte[body.Length];
            Assert.ThrowsExactly<AuthenticationTagMismatchException>(
                () => decryptor.Decrypt(0, wire.AsSpan(0, 4), wire.AsSpan(4), plaintext));
        }

        [TestMethod]
        public void DecryptPacketLength_is_an_identity_pass_through()
        {
            var transform = new GcmModeCryptoTransform(
                Key,
                Convert.FromHexString("00112233445566778899aabb"));

            var length = Convert.FromHexString("00001f40");

            Assert.AreEqual(8000, transform.DecryptPacketLength(5, length));
        }

        [TestMethod]
        public void Encrypt_rejects_short_destination()
        {
            var transform = new GcmModeCryptoTransform(
                Key,
                Convert.FromHexString("00112233445566778899aabb"));
            var frame = MakeFrame(Convert.FromHexString("00000004"), new byte[4]);

            Assert.ThrowsExactly<ArgumentException>(
                () => transform.Encrypt(0, frame, new byte[frame.Length + 15]));
        }

        [TestMethod]
        public void Constructor_validates_key_and_iv_lengths()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => new GcmModeCryptoTransform(new byte[24], Convert.FromHexString("00112233445566778899aabb")));
            Assert.ThrowsExactly<ArgumentException>(
                () => new GcmModeCryptoTransform(Key, new byte[11]));
            Assert.ThrowsExactly<ArgumentNullException>(
                () => new GcmModeCryptoTransform(null!, Convert.FromHexString("00112233445566778899aabb")));
            Assert.ThrowsExactly<ArgumentNullException>(
                () => new GcmModeCryptoTransform(Key, null!));
        }

        [TestMethod]
        public void TagBytes_is_always_sixteen()
        {
            var transform = new GcmModeCryptoTransform(
                Convert.FromHexString("000102030405060708090a0b0c0d0e0f"),
                Convert.FromHexString("00112233445566778899aabb"));

            Assert.AreEqual(16, transform.TagBytes);
        }
    }
}
