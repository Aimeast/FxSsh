using System;
using System.Security.Cryptography;
using FxSsh.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Crypto
{
    /// <summary>
    /// Ownership contract of the key-exchange configuration objects: each
    /// <see cref="CipherInfo"/> / <see cref="HmacInfo"/> wraps a native
    /// cipher/MAC instance and hands it to the transform it creates. Dispose
    /// must release the instance while the info still owns it (an AEAD
    /// direction or a failed handshake never builds a transform), and must
    /// leave it alone once a transform owns it.
    /// </summary>
    [TestClass]
    public sealed class AlgorithmInfoTests
    {
        private static readonly byte[] Key256 = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        private static readonly byte[] Iv16 = Convert.FromHexString("aabbccddeeff00112233445566778899");

        [TestMethod]
        public void CipherInfo_dispose_releases_an_unused_algorithm()
        {
            var algorithm = new TrackingSymmetricAlgorithm();
            var info = new CipherInfo(algorithm, 256, CipherModeEx.CBC);

            info.Dispose();
            info.Dispose(); // idempotent

            Assert.IsTrue(algorithm.Disposed,
                "an algorithm that never backed a transform must be released deterministically");
        }

        [TestMethod]
        public void CipherInfo_dispose_after_handoff_leaves_the_algorithm_to_the_transform()
        {
            var algorithm = new TrackingSymmetricAlgorithm();
            var info = new CipherInfo(algorithm, 256, CipherModeEx.CBC);
            var cipher = info.Cipher(Key256, Iv16, true);

            info.Dispose(); // ownership moved to the transform

            Assert.IsFalse(algorithm.Disposed, "the created transform owns the algorithm");
            cipher.Dispose();
            Assert.IsTrue(algorithm.Disposed, "disposing the transform releases the algorithm");
        }

        [TestMethod]
        public void CipherInfo_reports_only_AEAD_configurations_as_AEAD()
        {
            using var ctr = new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR);
            using var gcm = new CipherInfo(256);
            using var plugin = new CipherInfo(_ => throw new InvalidOperationException("not invoked"), 256, 128);

            Assert.IsFalse(ctr.IsAead);
            Assert.IsTrue(gcm.IsAead);
            Assert.IsTrue(plugin.IsAead);
        }

        [TestMethod]
        public void HmacInfo_dispose_releases_an_unused_algorithm()
        {
            var algorithm = new TrackingKeyedHashAlgorithm();
            var info = new HmacInfo(algorithm, 256);

            info.Dispose();
            info.Dispose(); // idempotent

            Assert.IsTrue(algorithm.Disposed,
                "a MAC that never backed a packet must be released deterministically");
        }

        [TestMethod]
        public void HmacInfo_dispose_after_handoff_leaves_the_algorithm_to_the_mac()
        {
            var algorithm = new TrackingKeyedHashAlgorithm();
            var info = new HmacInfo(algorithm, 256);
            var mac = info.Hmac(Key256);

            info.Dispose(); // ownership moved to the MAC

            Assert.IsFalse(algorithm.Disposed, "the created MAC owns the algorithm");
            mac.Dispose();
            Assert.IsTrue(algorithm.Disposed, "disposing the MAC releases the algorithm");
        }

        private sealed class TrackingSymmetricAlgorithm : SymmetricAlgorithm
        {
            public bool Disposed { get; private set; }

            public override int BlockSize { get; set; } = 128;

            public override KeySizes[] LegalKeySizes { get; } = [new KeySizes(128, 256, 64)];

            public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV) => new NullCryptoTransform();

            public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV) => new NullCryptoTransform();

            public override void GenerateIV()
            {
            }

            public override void GenerateKey()
            {
            }

            protected override void Dispose(bool disposing)
            {
                Disposed = true;
                base.Dispose(disposing);
            }
        }

        private sealed class NullCryptoTransform : ICryptoTransform
        {
            public bool CanReuseTransform => true;
            public bool CanTransformMultipleBlocks => true;
            public int InputBlockSize => 16;
            public int OutputBlockSize => 16;

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
                => inputCount;

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount) => [];

            public void Dispose()
            {
            }
        }

        private sealed class TrackingKeyedHashAlgorithm : KeyedHashAlgorithm
        {
            public bool Disposed { get; private set; }

            public override int HashSize => 256;

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
            }

            protected override byte[] HashFinal() => new byte[32];

            public override void Initialize()
            {
            }

            protected override void Dispose(bool disposing)
            {
                Disposed = true;
                base.Dispose(disposing);
            }
        }
    }
}
