using System;
using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class CipherInfo
    {
        public CipherInfo(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            if (!algorithm.LegalKeySizes.Any(x =>
                x.MinSize <= keySize && keySize <= x.MaxSize
                && (x.SkipSize == 0 ? keySize == x.MinSize : keySize % x.SkipSize == 0)))
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "Key size is not legal for the algorithm.");

            algorithm.KeySize = keySize;
            KeySize = algorithm.KeySize;
            BlockSize = algorithm.BlockSize;
            IVSize = BlockSize >> 3; // CBC/CTR: IV length equals block size in bytes.
            Cipher = (key, iv, isEncryption) => new EncryptionAlgorithm(algorithm, keySize, mode, key, iv, isEncryption);
        }

        /// <summary>
        /// AES-GCM constructor (RFC 5647). AesGcm is not a SymmetricAlgorithm,
        /// so it bypasses the LegalKeySizes machinery. The SSH GCM IV is the
        /// full 12-byte nonce material: the first 4 bytes are the fixed field
        /// and the last 8 bytes seed the invocation counter (per OpenSSL's
        /// EVP_CTRL_GCM_SET_IV_FIXED arg=-1 "copy the complete IV" semantics,
        /// NOT a 4-byte fixed_iv alone). AES block size (16) is still used for
        /// packet length / padding alignment, so BlockSize is reported as 16.
        /// </summary>
        public CipherInfo(int keySize)
        {
            if (keySize != 128 && keySize != 256)
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "AES-GCM key size must be 128 or 256 bits.");

            KeySize = keySize;
            BlockSize = 128; // AES block size in bits; BlockBytesSize derives 16 from this.
            IVSize = 12;    // RFC 5647 section 7.1 + OpenSSL SET_IV_FIXED(arg=-1): full 12-byte nonce from KEX.
            Cipher = (key, iv, isEncryption) => new EncryptionAlgorithm(null, keySize, CipherModeEx.GCM, key, iv, isEncryption);
        }

        /// <summary>
        /// Plugin AEAD constructor for ciphers supplied from outside the library
        /// (e.g. chacha20-poly1305@openssh.com, whose transform lives in
        /// FxSsh.Tests). <paramref name="createTransform"/> builds a per-direction
        /// IAeadTransform from the KEX-derived key (called once for the client
        /// and once for the server direction with their respective keys). The IV
        /// slot is unused -- IVSize is 0, these ciphers key their per-packet
        /// nonce off the packet sequence number -- and <paramref name="blockSizeBits"/>
        /// drives packet_length / padding alignment (64 bits = 8 bytes for
        /// chacha20-poly1305@openssh.com).
        /// </summary>
        public CipherInfo(Func<byte[], IAeadTransform> createTransform, int keySize, int blockSizeBits)
        {
            ArgumentNullException.ThrowIfNull(createTransform);
            if (keySize <= 0 || keySize % 8 != 0)
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "Key size must be a positive multiple of 8 bits.");
            if (blockSizeBits <= 0 || blockSizeBits % 8 != 0)
                throw new ArgumentOutOfRangeException(nameof(blockSizeBits), blockSizeBits, "Block size must be a positive multiple of 8 bits.");

            KeySize = keySize;
            BlockSize = blockSizeBits;
            IVSize = 0;
            Cipher = (key, iv, isEncryption) => new EncryptionAlgorithm(createTransform(key), blockSizeBits >> 3);
        }

        public int KeySize { get; private set; }

        /// <summary>Block size in bits (used for padding alignment).</summary>
        public int BlockSize { get; private set; }

        /// <summary>IV length in bytes for key-exchange IV derivation (4 for GCM).</summary>
        public int IVSize { get; private set; }

        public Func<byte[], byte[], bool, EncryptionAlgorithm> Cipher { get; private set; }
    }
}
