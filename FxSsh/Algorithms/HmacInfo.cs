using System;
using System.Security.Cryptography;
using System.Threading;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the configuration of an SSH packet MAC (HMAC per RFC 2104,
    /// applied to the binary packet protocol per RFC 4253 section 6.4): the
    /// MAC key size, whether the Encrypt-then-MAC form is used, and a factory
    /// that builds the per-direction <see cref="HmacAlgorithm"/> from the
    /// key-exchange-derived key.
    /// </summary>
    /// <remarks>
    /// The algorithm-taking constructor is single-use: the <see cref="Hmac"/>
    /// factory hands the wrapped <see cref="KeyedHashAlgorithm"/> to the
    /// created <see cref="HmacAlgorithm"/>, which disposes it when the MAC is
    /// released. Invoking that factory a second time - for example by
    /// sharing one instance between the two directions or across a rekey -
    /// wraps an already-disposed algorithm. Create a fresh HmacInfo per
    /// factory invocation, as the seeded catalog factories do. (The plugin
    /// constructor is exempt: its <c>create</c> delegate is expected to
    /// build a new instance per call.)
    /// </remarks>
    public class HmacInfo : IDisposable
    {
        private readonly KeyedHashAlgorithm _algorithm;
        private int _handedOff;

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacInfo"/> class from
        /// a keyed hash algorithm instance. Each invocation of
        /// <see cref="Hmac"/> creates a fresh <see cref="HmacAlgorithm"/> that
        /// wraps this algorithm with the supplied key and owns (disposes) it,
        /// so create a separate <see cref="HmacInfo"/> for each direction
        /// instead of sharing one instance.
        /// </summary>
        /// <param name="algorithm">The keyed hash algorithm backing the MAC, such as <see cref="HMACSHA256"/> or <see cref="HMACSHA512"/>.</param>
        /// <param name="keySize">The MAC key size in bits.</param>
        /// <param name="isEtm">True to select the Encrypt-then-MAC form (OpenSSH -etm@openssh.com extension), in which the MAC covers the ciphertext instead of the plaintext.</param>
        public HmacInfo(KeyedHashAlgorithm algorithm, int keySize, bool isEtm = false)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            KeySize = keySize;
            IsEtm = isEtm;
            _algorithm = algorithm;
            Hmac = key =>
            {
                // Only a successfully built MAC takes ownership of the
                // wrapped algorithm; if construction throws, Dispose below
                // still releases it.
                var mac = new HmacAlgorithm(algorithm, keySize, key);
                Interlocked.Exchange(ref _handedOff, 1);
                return mac;
            };
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

        /// <summary>
        /// Releases the wrapped <see cref="KeyedHashAlgorithm"/> when no MAC
        /// was ever created from this configuration. Once <see cref="Hmac"/>
        /// has handed the algorithm to an <see cref="HmacAlgorithm"/>, that
        /// MAC owns it and this method is a no-op. Key exchange calls it when
        /// a direction is AEAD or the exchange fails, so a native HMAC that
        /// was never used is released deterministically instead of waiting
        /// for the finalizer.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _handedOff, 1) == 0)
                _algorithm?.Dispose();
        }
    }
}
