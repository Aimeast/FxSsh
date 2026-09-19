using System;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Crypto
{
    [TestClass]
    public sealed class EncryptionAlgorithmTests
    {
        private static readonly byte[] Key256 = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        private static readonly byte[] Iv16 = Convert.FromHexString("aabbccddeeff00112233445566778899");
        private static readonly byte[] Iv12 = Convert.FromHexString("00112233445566778899aabb");

        private static EncryptionAlgorithm Create(CipherModeEx mode, byte[] key, byte[] iv, bool isEncryption) =>
            new CipherInfo(Aes.Create(), key.Length << 3, mode).Cipher(key, iv, isEncryption);

        [TestMethod]
        public void Cbc_round_trips_block_aligned_data()
        {
            var plaintext = new byte[64];
            Random.Shared.NextBytes(plaintext);

            var cipher = Create(CipherModeEx.CBC, Key256, Iv16, true);
            var decrypted = Create(CipherModeEx.CBC, Key256, Iv16, false);

            var ciphertext = cipher.Transform(plaintext);

            Assert.AreEqual(64, ciphertext.Length);
            CollectionAssert.AreEqual(plaintext, decrypted.Transform(ciphertext));
        }

        [TestMethod]
        public void Ctr_round_trips_unaligned_data_for_every_key_size()
        {
            var plaintext = new byte[37];
            Random.Shared.NextBytes(plaintext);

            foreach (var keySize in new[] { 128, 192, 256 })
            {
                var key = new byte[keySize >> 3];
                Random.Shared.NextBytes(key);

                var cipher = new CipherInfo(Aes.Create(), keySize, CipherModeEx.CTR).Cipher(key, (byte[])Iv16.Clone(), true);
                var decrypted = new CipherInfo(Aes.Create(), keySize, CipherModeEx.CTR).Cipher(key, (byte[])Iv16.Clone(), false);

                CollectionAssert.AreEqual(plaintext, decrypted.Transform(cipher.Transform(plaintext)), $"keySize {keySize}");
            }
        }

        [TestMethod]
        public void Transform_processes_block_aligned_lengths_from_a_larger_buffer()
        {
            // Session holds a rented buffer bigger than the packet and passes
            // the exact packet length: two 16-byte calls must produce the
            // same stream as one 32-byte call. (SSH packet bodies are always
            // block aligned, so per-call lengths are block multiples.)
            var plaintext = new byte[32];
            Random.Shared.NextBytes(plaintext);

            var cipher = Create(CipherModeEx.CTR, Key256, Iv16, true);
            var reference = Create(CipherModeEx.CTR, Key256, Iv16, true);

            var pooled = new byte[64]; // stands in for a rented buffer of zeros
            var first = new byte[16];
            var second = new byte[16];
            var expected = new byte[32];

            cipher.Transform(pooled, 16, first);
            cipher.Transform(pooled, 16, second);

            // Reference keystream: one-shot over the same counter range.
            var zeros = new byte[32];
            reference.Transform(zeros, 32, expected);

            CollectionAssert.AreEqual(expected[..16], first);
            CollectionAssert.AreEqual(expected[16..], second);
        }

        [TestMethod]
        public void Transform_supports_in_place_operation()
        {
            var original = new byte[48];
            Random.Shared.NextBytes(original);
            var buffer = (byte[])original.Clone();

            var cipher = Create(CipherModeEx.CTR, Key256, Iv16, true);
            var decrypted = Create(CipherModeEx.CTR, Key256, Iv16, false);

            cipher.Transform(buffer, buffer.Length, buffer);
            decrypted.Transform(buffer, buffer.Length, buffer);

            CollectionAssert.AreEqual(original, buffer);
        }

        [TestMethod]
        public void Transform_validates_offsets()
        {
            var cipher = Create(CipherModeEx.CTR, Key256, Iv16, true);

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => cipher.Transform(new byte[16], 8, 16, new byte[16], 0));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => cipher.Transform(new byte[16], 0, 16, new byte[16], 8));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => cipher.Transform(new byte[16], 0, -1, new byte[16], 0));
        }

        [TestMethod]
        public void Key_size_must_match_the_key_length()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => new EncryptionAlgorithm(Aes.Create(), 128, CipherModeEx.CTR, Key256, Iv16, true));
        }

        [TestMethod]
        public void Gcm_exposes_aead_semantics_and_round_trips()
        {
            var info = new CipherInfo(256);
            Assert.AreEqual(12, info.IVSize);
            Assert.AreEqual(128, info.BlockSize);

            var cipher = info.Cipher(Key256, (byte[])Iv12.Clone(), true);
            var decipher = info.Cipher(Key256, (byte[])Iv12.Clone(), false);

            Assert.IsTrue(cipher.IsAead);
            Assert.AreEqual(16, cipher.BlockBytesSize);
            Assert.AreEqual(16, cipher.TagBytes);

            var packetLength = Convert.FromHexString("00000014");
            var body = new byte[20];
            Random.Shared.NextBytes(body);
            var frame = new byte[24];
            packetLength.CopyTo(frame, 0);
            body.CopyTo(frame, 4);

            var wire = new byte[frame.Length + cipher.TagBytes];
            cipher.EncryptAead(0, frame, wire);

            Assert.AreEqual(0x14, decipher.DecryptPacketLength(0, wire.AsSpan(0, 4)));

            var plaintext = new byte[body.Length];
            decipher.DecryptAead(0, wire.AsSpan(0, 4), wire.AsSpan(4), plaintext);

            CollectionAssert.AreEqual(body, plaintext);
        }

        [TestMethod]
        public void Streaming_and_aead_paths_are_mutually_exclusive()
        {
            var ctr = Create(CipherModeEx.CTR, Key256, Iv16, true);
            Assert.ThrowsExactly<InvalidOperationException>(() => ctr.EncryptAead(0, new byte[16], new byte[32]));
            Assert.ThrowsExactly<InvalidOperationException>(() => ctr.DecryptPacketLength(0, new byte[4]));
            Assert.ThrowsExactly<InvalidOperationException>(() => ctr.DecryptAead(0, new byte[4], new byte[20], new byte[16]));
            Assert.ThrowsExactly<InvalidOperationException>(() => ctr.TagBytes);

            var gcm = new CipherInfo(128).Cipher(new byte[16], (byte[])Iv12.Clone(), true);
            Assert.ThrowsExactly<InvalidOperationException>(() => gcm.Transform(new byte[16]));
        }

        [TestMethod]
        public void Gcm_requires_a_twelve_byte_iv()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => new EncryptionAlgorithm(null!, 256, CipherModeEx.GCM, Key256, new byte[11], true));
        }

        [TestMethod]
        public void Plugin_aead_constructor_delegates_to_the_transform()
        {
            var plugin = new FakeAeadTransform();
            var cipher = new EncryptionAlgorithm(plugin, blockBytesSize: 8);

            Assert.IsTrue(cipher.IsAead);
            Assert.AreEqual(8, cipher.BlockBytesSize);
            Assert.AreEqual(FakeAeadTransform.TagSize, cipher.TagBytes);

            var frame = new byte[12];
            var destination = new byte[12 + FakeAeadTransform.TagSize];
            cipher.EncryptAead(5, frame, destination);
            CollectionAssert.AreEqual(plugin.LastEncryptOutput, destination);

            Assert.AreEqual(0x1234, cipher.DecryptPacketLength(5, Convert.FromHexString("00001234")));
        }

        [TestMethod]
        public void Plugin_aead_constructor_validates_arguments()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new EncryptionAlgorithm(null!, 8));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new EncryptionAlgorithm(new FakeAeadTransform(), 0));
        }

        [TestMethod]
        public void CipherInfo_validates_key_sizes()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new CipherInfo(Aes.Create(), 100, CipherModeEx.CTR));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new CipherInfo(192));
            Assert.ThrowsExactly<ArgumentNullException>(() => new CipherInfo(null!, 256, CipherModeEx.CBC));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new CipherInfo(_ => new FakeAeadTransform(), 0, 64));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new CipherInfo(_ => new FakeAeadTransform(), 256, 0));
        }

        [TestMethod]
        public void CipherInfo_reports_cbc_dimensions()
        {
            var info = new CipherInfo(Aes.Create(), 256, CipherModeEx.CBC);

            Assert.AreEqual(256, info.KeySize);
            Assert.AreEqual(128, info.BlockSize);
            Assert.AreEqual(16, info.IVSize);
        }

        private sealed class FakeAeadTransform : IAeadTransform
        {
            public const int TagSize = 8;

            public byte[] LastEncryptOutput { get; private set; } = Array.Empty<byte>();

            public int TagBytes => TagSize;

            public int DecryptPacketLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength) =>
                encryptedLength[0] << 24 | encryptedLength[1] << 16 | encryptedLength[2] << 8 | encryptedLength[3];

            public void Encrypt(uint sequenceNumber, ReadOnlySpan<byte> frame, Span<byte> destination)
            {
                frame.CopyTo(destination);
                destination[frame.Length..].Fill((byte)sequenceNumber);
                LastEncryptOutput = destination.ToArray();
            }

            public void Decrypt(uint sequenceNumber, ReadOnlySpan<byte> lengthField, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
            {
                ciphertextWithTag[..plaintextDestination.Length].CopyTo(plaintextDestination);
            }
        }
    }
}
