using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class HmacInfo
    {
        public HmacInfo(KeyedHashAlgorithm algorithm, int keySize, bool isEtm = false)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            KeySize = keySize;
            IsEtm = isEtm;
            Hmac = key => new HmacAlgorithm(algorithm, keySize, key);
        }

        /// <summary>
        /// Plugin constructor for MAC algorithms implemented outside the
        /// library (e.g. umac-64@openssh.com / umac-128@openssh.com in
        /// FxSsh.Tests). <paramref name="create"/> builds a per-direction
        /// HmacAlgorithm from the KEX-derived key (called once for the client
        /// and once for the server direction with their respective keys).
        /// Mirrors the plugin AEAD constructor on <see cref="CipherInfo"/>.
        /// </summary>
        public HmacInfo(Func<byte[], HmacAlgorithm> create, int keySize, bool isEtm = false)
        {
            ArgumentNullException.ThrowIfNull(create);
            if (keySize <= 0 || keySize % 8 != 0)
                throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "Key size must be a positive multiple of 8 bits.");

            KeySize = keySize;
            IsEtm = isEtm;
            Hmac = create;
        }

        public int KeySize { get; private set; }

        /// <summary>
        /// True for Encrypt-then-MAC algorithms (-etm@openssh.com, RFC 6668).
        /// When true, the MAC covers the ciphertext instead of the plaintext.
        /// </summary>
        public bool IsEtm { get; private set; }

        public Func<byte[], HmacAlgorithm> Hmac { get; private set; }
    }
}
