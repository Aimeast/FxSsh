using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the server side of the elliptic curve Diffie-Hellman key
    /// exchange over the NIST curves nistp256, nistp384, and nistp521
    /// (RFC 5656).
    /// </summary>
    public class EcdhKex : KexAlgorithm
    {
        private readonly ECDiffieHellman _ecdh;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdhKex"/> class, generating
        /// an ephemeral key pair on the named curve and selecting the matching hash
        /// algorithm (SHA-256, SHA-384, or SHA-512).
        /// </summary>
        /// <param name="curveName">The curve name: nistp256, nistp384, or nistp521.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="curveName"/> is not nistp256, nistp384, or nistp521.</exception>
        public EcdhKex(string curveName)
        {
            if (curveName != "nistp256" && curveName != "nistp384" && curveName != "nistp521")
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, "Curve name must be nistp256, nistp384 or nistp521.");

            if (curveName == "nistp256")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                _hashAlgorithm = SHA256.Create();
            }
            else if (curveName == "nistp384")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
                _hashAlgorithm = SHA384.Create();
            }
            else if (curveName == "nistp521")
            {
                _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521);
                _hashAlgorithm = SHA512.Create();
            }
        }

        /// <summary>
        /// Exports the server's ephemeral public point Q_S in uncompressed form.
        /// </summary>
        /// <returns>
        /// Q_S as a 0x04 byte followed by the X and Y coordinates as big-endian
        /// byte arrays, not SSH-framed.
        /// </returns>
        public override byte[] CreateKeyExchange()
        {
            var q = _ecdh.PublicKey.ExportParameters().Q;
            return new SshDataWriter(1 + q.X.Length + q.Y.Length)
                .Write(0x04)
                .WriteBytes(q.X)
                .WriteBytes(q.Y)
                .ToByteArray();
        }

        /// <summary>
        /// Derives the ECDH shared secret from the client's ephemeral public point Q_C.
        /// </summary>
        /// <param name="exchangeData">Q_C in uncompressed form: a 0x04 byte followed by the X and Y coordinates.</param>
        /// <returns>The raw shared secret as a big-endian two's-complement byte array, not SSH-framed.</returns>
        /// <exception cref="InvalidDataException"><paramref name="exchangeData"/> does not start with the 0x04 uncompressed-point marker.</exception>
        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            ArgumentNullException.ThrowIfNull(exchangeData);

            var reader = new SshDataReader(exchangeData);
            if (reader.ReadByte() != 0x04)
                throw new InvalidDataException();
            var qlength = (exchangeData.Length - 1) / 2;
            var args = new ECParameters();
            args.Curve = _ecdh.PublicKey.ExportParameters().Curve;
            args.Q = new ECPoint { X = reader.ReadBytes(qlength), Y = reader.ReadBytes(qlength) };

            var clientPublicKey = ECDiffieHellman.Create(args).PublicKey;
            var agreement = _ecdh.DeriveRawSecretAgreement(clientPublicKey);
            var sharedSecret = new BigInteger(agreement, isUnsigned: true, isBigEndian: true)
                .ToByteArray(isUnsigned: false, isBigEndian: true);

            return sharedSecret;
        }
    }
}
