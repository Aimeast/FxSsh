using System;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// The ssh-rsa host key algorithm with RSA/SHA-2 signatures (RFC 8332).
    /// Keys are stored as PKCS#8/PEM; the public key blob keeps the classic
    /// "ssh-rsa" format, while signatures are named rsa-sha2-256 or
    /// rsa-sha2-512 on the wire.
    /// </summary>
    public class RsaKey : PublicKeyAlgorithm
    {
        private readonly RSA _algorithm = RSA.Create();
        private readonly string _name;
        private readonly HashAlgorithmName _sha;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKey"/> class.
        /// </summary>
        /// <param name="sha2Bitlen">The signature hash size in bits: 256 selects rsa-sha2-256 (SHA-256) and 512 selects rsa-sha2-512 (SHA-512).</param>
        /// <param name="key">The key in PEM format, or an empty string to start without a key.</param>
        /// <exception cref="ArgumentException"><paramref name="sha2Bitlen"/> is neither 256 nor 512.</exception>
        public RsaKey(int sha2Bitlen, string key)
            : base(key)
        {
            switch (sha2Bitlen)
            {
                case 256:
                    _name = "rsa-sha2-256";
                    _sha = HashAlgorithmName.SHA256;
                    break;
                case 512:
                    _name = "rsa-sha2-512";
                    _sha = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new ArgumentException("sha2Bitlen must equal 256, or 512", nameof(sha2Bitlen));
            }
        }

        /// <summary>
        /// Gets the signature algorithm name: "rsa-sha2-256" or "rsa-sha2-512",
        /// per RFC 8332 section 3.
        /// </summary>
        public override string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Gets the key blob format name, always "ssh-rsa" (RFC 4253 section 6.6).
        /// </summary>
        public override string PublicKeyName
        {
            get { return "ssh-rsa"; }
        }

        /// <summary>
        /// Imports a PEM-encoded key (PKCS#8 private key or SPKI public key,
        /// plus the other PEM forms accepted by RSA.ImportFromPem).
        /// </summary>
        /// <param name="key">The PEM-encoded key.</param>
        public override void ImportKey(string key)
        {
            _algorithm.ImportFromPem(key);
        }

        /// <summary>
        /// Exports the private key as PKCS#8 PEM.
        /// </summary>
        /// <returns>The PEM-encoded private key.</returns>
        public override string ExportKey()
        {
            return _algorithm.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Loads an RSA public key from its "ssh-rsa" wire blob: the name
        /// string followed by the exponent and modulus as mpint values.
        /// </summary>
        /// <param name="data">The key blob.</param>
        /// <exception cref="CryptographicException">The blob names a different key format.</exception>
        public override void LoadKeyAndCertificatesData(byte[] data)
        {
            var reader = new SshDataReader(data);
            if (reader.ReadString(Encoding.ASCII) != PublicKeyName)
                throw new CryptographicException("Key and certificates were not created with this algorithm.");

            var args = new RSAParameters
            {
                Exponent = reader.ReadMpint(),
                Modulus = reader.ReadMpint(),
            };

            _algorithm.ImportParameters(args);
        }

        /// <summary>
        /// Serializes the public key to the "ssh-rsa" wire blob: the name
        /// string followed by the exponent and modulus as mpint values
        /// (RFC 4253 section 6.6).
        /// </summary>
        /// <returns>The key blob.</returns>
        public override byte[] CreateKeyAndCertificatesData()
        {
            var args = _algorithm.ExportParameters(false);
            return new SshDataWriter(8 + PublicKeyName.Length + args.Exponent.Length + args.Modulus.Length)
                .Write(PublicKeyName, Encoding.ASCII)
                .WriteMpint(args.Exponent)
                .WriteMpint(args.Modulus)
                .ToByteArray();
        }

        /// <summary>
        /// Verifies an RSASSA-PKCS1-v1_5 signature over the data, using the
        /// hash selected at construction.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The raw signature.</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyData(byte[] data, byte[] signature)
        {
            return _algorithm.VerifyData(data, signature, _sha, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Verifies an RSASSA-PKCS1-v1_5 signature over a pre-computed hash.
        /// </summary>
        /// <param name="hash">The signed hash.</param>
        /// <param name="signature">The raw signature.</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            return _algorithm.VerifyHash(hash, signature, _sha, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Signs the data with RSASSA-PKCS1-v1_5 using the hash selected at
        /// construction.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>The raw signature.</returns>
        public override byte[] SignData(byte[] data)
        {
            return _algorithm.SignData(data, _sha, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Signs a pre-computed hash with RSASSA-PKCS1-v1_5.
        /// </summary>
        /// <param name="hash">The hash to sign.</param>
        /// <returns>The raw signature.</returns>
        public override byte[] SignHash(byte[] hash)
        {
            return _algorithm.SignHash(hash, _sha, RSASignaturePadding.Pkcs1);
        }
    }
}
