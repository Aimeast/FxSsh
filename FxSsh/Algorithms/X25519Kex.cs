using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// X25519 key exchange (curve25519-sha256) per RFC 8731.
    /// Uses the platform-native X25519DiffieHellman (net11+) - no external dependencies,
    /// no hand-rolled crypto.
    /// </summary>
    public class X25519Kex : KexAlgorithm
    {
        private const int PublicKeySize = 32;

        private readonly X25519DiffieHellman _x25519;

        /// <summary>
        /// Initializes a new instance of the <see cref="X25519Kex"/> class,
        /// generating an X25519 key pair and selecting SHA-256.
        /// </summary>
        public X25519Kex()
        {
            _x25519 = X25519DiffieHellman.GenerateKey();
            _hashAlgorithm = SHA256.Create();
        }

        /// <summary>
        /// Exports the server's 32-byte X25519 public key Q_S (the u-coordinate),
        /// without the 0x04 point prefix used by NIST-curve ECDH (RFC 8731 section 2).
        /// </summary>
        /// <returns>The raw 32-byte X25519 public key, not SSH-framed.</returns>
        public override byte[] CreateKeyExchange()
        {
            // RFC 8731 section 2: Q_S is the 32-byte X25519 u-coordinate sent as an
            // SSH string, WITHOUT the 0x04 point prefix used by NIST-curve ECDH.
            return _x25519.ExportPublicKey();
        }

        /// <summary>
        /// Derives the X25519 shared secret from the client's public key Q_C.
        /// </summary>
        /// <param name="exchangeData">The client's 32-byte X25519 public key.</param>
        /// <returns>The shared secret as a big-endian two's-complement byte array, not SSH-framed.</returns>
        /// <exception cref="InvalidDataException"><paramref name="exchangeData"/> is not 32 bytes long.</exception>
        /// <exception cref="CryptographicException">The derived shared secret is all zeros, i.e. the client sent a low-order point (RFC 7748 section 6.1).</exception>
        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            ArgumentNullException.ThrowIfNull(exchangeData);
            if (exchangeData.Length != PublicKeySize)
                throw new InvalidDataException("X25519 public key must be 32 bytes.");

            var sharedSecret = _x25519.DeriveRawSecretAgreement(exchangeData);

            // RFC 7748 section 6.1: an all-zero shared secret means the peer's
            // public key is a low-order point; abort the exchange.
            if (sharedSecret.All(b => b == 0))
                throw new CryptographicException("X25519 shared secret is all zeros.");

            // SSH mpint encoding: the 32-byte big-endian value with a leading 0x00
            // prepended when the high bit is set (same approach as EcdhKex).
            return new BigInteger(sharedSecret, isUnsigned: true, isBigEndian: true)
                .ToByteArray(isUnsigned: false, isBigEndian: true);
        }
    }
}
