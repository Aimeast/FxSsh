using System;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Crypto
{
    [TestClass]
    public sealed class HmacAlgorithmTests
    {
        private static readonly byte[] Key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        private static byte[] Seq(uint sequence)
        {
            var bytes = new byte[4];
            bytes[0] = (byte)(sequence >> 24);
            bytes[1] = (byte)(sequence >> 16);
            bytes[2] = (byte)(sequence >> 8);
            bytes[3] = (byte)sequence;
            return bytes;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var total = 0;
            foreach (var part in parts)
            {
                total += part.Length;
            }

            var result = new byte[total];
            var offset = 0;
            foreach (var part in parts)
            {
                part.CopyTo(result, offset);
                offset += part.Length;
            }

            return result;
        }

        [TestMethod]
        public void Mac_covers_seq_then_a_then_b_in_order()
        {
            var a = new byte[] { 0x01, 0x02 };
            var b = new byte[] { 0x03, 0x04, 0x05 };
            var hmac = new HmacAlgorithm(new HMACSHA256(), 256, (byte[])Key.Clone());

            // The SSH packet MAC is defined over seq || a || b (RFC 4253
            // 6.4); cross-check the exact concatenation against the platform
            // HMAC with the same key.
            var expected = HMACSHA256.HashData(Key, Concat(Seq(7), a, b));
            var actual = hmac.ComputeHash(a, b, 7);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Mac_matches_the_platform_reference_for_sha512()
        {
            var a = Convert.FromHexString("00112233445566778899aabbccddeeff");
            var hmac = new HmacAlgorithm(new HMACSHA512(), 256, (byte[])Key.Clone());

            var expected = HMACSHA512.HashData(Key, Concat(Seq(1), a));
            var actual = hmac.ComputeHash(a, Array.Empty<byte>(), 1);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Single_input_overload_prepends_a_zero_sequence()
        {
            var hmac = new HmacAlgorithm(new HMACSHA256(), 256, (byte[])Key.Clone());
            var input = new byte[] { 0x0A, 0x0B, 0x0C };

            var actual = hmac.ComputeHash(input);
            var expected = HMACSHA256.HashData(Key, Concat(new byte[4], input));

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Span_overload_matches_the_array_overload()
        {
            var a = Convert.FromHexString("00112233445566778899aabbccddeeff");
            var b = Convert.FromHexString("0102030405060708");
            var hmac = new HmacAlgorithm(new HMACSHA256(), 256, (byte[])Key.Clone());

            var expected = hmac.ComputeHash(a, b, 99);

            var destination = new byte[hmac.DigestLength];
            hmac.ComputeHash(a, b, 99, destination);

            CollectionAssert.AreEqual(expected, destination);
        }

        [TestMethod]
        public void Span_overload_rejects_short_destination()
        {
            var hmac = new HmacAlgorithm(new HMACSHA256(), 256, (byte[])Key.Clone());

            Assert.ThrowsExactly<ArgumentException>(
                () => hmac.ComputeHash(new byte[] { 1 }, Array.Empty<byte>(), 0, new byte[hmac.DigestLength - 1]));
        }

        [TestMethod]
        public void Digest_length_follows_the_hash_size()
        {
            var sha256 = new HmacAlgorithm(new HMACSHA256(), 256, (byte[])Key.Clone());
            var sha512 = new HmacAlgorithm(new HMACSHA512(), 256, (byte[])Key.Clone());

            Assert.AreEqual(32, sha256.DigestLength);
            Assert.AreEqual(64, sha512.DigestLength);
        }

        [TestMethod]
        public void Non_sha2_keyed_hash_uses_the_streaming_fallback()
        {
            var a = new byte[] { 0x0A, 0x0B };
            var hmac = new HmacAlgorithm(new HMACMD5(), 128, new byte[16]);

            var expected = HMACMD5.HashData(new byte[16], Concat(Seq(3), a));
            var actual = hmac.ComputeHash(a, Array.Empty<byte>(), 3);

            CollectionAssert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Constructor_validates_key_size()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => new HmacAlgorithm(new HMACSHA256(), 128, (byte[])Key.Clone()));
            Assert.ThrowsExactly<ArgumentNullException>(
                () => new HmacAlgorithm(null!, 256, (byte[])Key.Clone()));
            Assert.ThrowsExactly<ArgumentNullException>(
                () => new HmacAlgorithm(new HMACSHA256(), 256, null!));
        }

        private sealed class TruncatedHmac : HmacAlgorithm
        {
            private readonly byte[] _key;

            public TruncatedHmac(byte[] key)
            {
                _key = key;
            }

            public override int DigestLength => 10;

            // Plugin MACs built through the protected parameterless
            // constructor implement the whole MAC themselves (the base core
            // has no digest configured) - e.g. umac-64@openssh.com would.
            public override void ComputeHash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint sequence, Span<byte> destination)
            {
                Span<byte> seq = stackalloc byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(seq, sequence);

                var total = 4 + a.Length + b.Length;
                Span<byte> concat = total <= 512 ? stackalloc byte[total] : new byte[total];
                seq.CopyTo(concat);
                a.CopyTo(concat[4..]);
                b.CopyTo(concat[(4 + a.Length)..]);

                Span<byte> full = stackalloc byte[32];
                HMACSHA256.HashData(_key, concat, full);
                full[..DigestLength].CopyTo(destination);
            }
        }

        [TestMethod]
        public void Plugin_mac_can_truncate_the_digest()
        {
            // HmacInfo's plugin constructor exists for truncated MACs such as
            // umac-64: a subclass overrides DigestLength and the Span core.
            var truncated = new TruncatedHmac(Key);

            Assert.AreEqual(10, truncated.DigestLength);

            var destination = new byte[10];
            truncated.ComputeHash(new byte[] { 1 }, Array.Empty<byte>(), 0, destination);

            var expected = HMACSHA256.HashData(Key, Concat(new byte[4], new byte[] { 1 }));
            CollectionAssert.AreEqual(expected[..10], destination);
        }
    }
}
