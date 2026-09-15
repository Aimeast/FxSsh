using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the configuration of an SSH packet MAC (HMAC per RFC 2104,
    /// applied to the binary packet protocol per RFC 4253 section 6.4): the
    /// MAC key size, whether the Encrypt-then-MAC form is used, and a factory
    /// that builds the per-direction <see cref="HmacAlgorithm"/> from the
    /// key-exchange-derived key.
    /// </summary>
    public class HmacInfo
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacInfo"/> class from
        /// a keyed hash algorithm instance. Each invocation of
        /// <see cref="Hmac"/> creates a fresh <see cref="HmacAlgorithm"/> that
        /// wraps this algorithm with the supplied key.
        /// </summary>
        /// <param name="algorithm">The keyed hash algorithm backing the MAC, such as <see cref="HMACSHA256"/> or <see cref="HMACSHA512"/>.</param>
        /// <param name="keySize">The MAC key size in bits.</param>
        /// <param name="isEtm">True to select the Encrypt-then-MAC form (OpenSSH -etm@openssh.com extension), in which the MAC covers the ciphertext instead of the plaintext.</param>
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

        /// <summary>Gets the MAC key size in bits.</summary>
        public int KeySize { get; private set; }

        /// <summary>
        /// True for Encrypt-then-MAC algorithms (OpenSSH -etm@openssh.com extension).
        /// When true, the MAC covers the ciphertext instead of the plaintext.
        /// </summary>
        public bool IsEtm { get; private set; }

        /// <summary>
        /// Gets the factory that creates the per-direction
        /// <see cref="HmacAlgorithm"/> from the MAC key derived by key exchange.
        /// </summary>
        public Func<byte[], HmacAlgorithm> Hmac { get; private set; }
    }
}
