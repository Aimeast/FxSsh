using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// The Ed25519 host key algorithm using Edwards Curve 25519
    /// (<see href="https://www.rfc-editor.org/info/rfc8709/">RFC 8709</see>)
    /// producing <c>ssh-ed25519</c> key type signatures.
    /// Keys are stored as PKCS#8/PEM; signatures are exchanged via
    /// the 32-byte encoded public point.
    /// </summary>
    /// <remarks>
    /// Ed25519 SSH keys provide strong cryptographic security, excellent
    /// performance and compact size, making them the modern default for
    /// secure SSH authentication.
    /// <para>
    /// Unfortunately, the .NET base class library does not yet provide
    /// a built-in implementation of Ed25519, so this Public Key Algorithm
    /// implementation relies on the Bouncy Castle Crypto library, and
    /// therefore implemented in a separate package that can be <i>plugged</i>
    /// into a FxSsh Algorithm Catalog.
    /// </para>
    /// </remarks>
    public class Ed25519Key : PublicKeyAlgorithm
    {
        /// <summary>
        /// Standard name for the algorithm in SSH protocol exchanges and host key files.
        /// </summary>
        public const string SshAlgorithmName = "ssh-ed25519";

        private readonly HashAlgorithmName _sha = HashAlgorithmName.SHA256;

        private Ed25519PrivateKeyParameters? _prvKey;
        private Ed25519PublicKeyParameters? _pubKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="Ed25519Key"/> class. 
        /// </summary>
        /// <param name="key">The key in PEM format, or an empty string to start without a key.</param>
        /// <remarks>
        /// Unlike other supported public key types (e.g. <see cref="RsaKey"/> and <see cref="EcdsaKey"/>),
        /// the standard Edwards Curve 25519 public key algorithm does not take any parameters, and always
        /// has a fixed size of 32 bytes (256 bits) for both private and public keys (64 bytes for the
        /// signature).
        /// </remarks>
        public Ed25519Key(string key) : base(key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                var gen = new Ed25519KeyPairGenerator();
                gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var pair = gen.GenerateKeyPair();
                _prvKey = (Ed25519PrivateKeyParameters)pair.Private;
                _pubKey = (Ed25519PublicKeyParameters)pair.Public;
            }
        }

        /// <summary>
        /// One-shot helper to generate Ed25519 private key in PEM format.
        /// </summary>
        /// <returns></returns>
        public static string GeneratePrivateKeyPem()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var prvKey = (Ed25519PrivateKeyParameters)pair.Private;
            var pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(prvKey).GetEncoded();
            var pkcs8Pem = PemEncoding.Write("PRIVATE KEY", pkcs8);
            return new(pkcs8Pem);
        }

        /// <summary>
        /// Gets the SSH protocol name of the algorithm.
        /// </summary>
        public override string Name => SshAlgorithmName;


        /// <summary>
        /// Gets the name used to identify the public key on the wire.
        /// </summary>
        public override string PublicKeyName => base.PublicKeyName;

        /// <summary>
        /// Imports a PEM-encoded key (PKCS#8 private key or SPKI public key,
        /// plus the other PEM forms accepted by PemReader).
        /// </summary>
        /// <param name="key">The PEM-encoded key.</param>
        public override void ImportKey(string key)
        {
            using var reader = new PemReader(new StringReader(key));
            _prvKey = (Ed25519PrivateKeyParameters)reader.ReadObject();
            _pubKey = _prvKey.GeneratePublicKey();
        }

        /// <summary>
        /// Exports the private key as PKCS#8 PEM.
        /// </summary>
        /// <returns>The PEM-encoded private key.</returns>
        public override string ExportKey()
        {
            var pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_prvKey).GetEncoded();
            var pkcs8Pem = PemEncoding.Write("PRIVATE KEY", pkcs8);
            return new(pkcs8Pem);
        }

        /// <summary>
        /// Serializes the public key to the SSH wire blob: the algorithm
        /// name string followed by the public point.
        /// </summary>
        /// <returns>The key blob.</returns>
        public override byte[] CreateKeyAndCertificatesData()
        {
            var point = _pubKey!.GetEncoded();
            return new SshDataWriter(this.Name.Length + point.Length)
                .Write(this.PublicKeyName, Encoding.ASCII)
                .WriteBinary(point)
                .ToByteArray();
        }

        /// <summary>
        /// Loads an Ed25519 public key from its SSH wire blob: the algorithm
        /// name string followed by the public point.
        /// </summary>
        /// <param name="data">The key blob.</param>
        public override void LoadKeyAndCertificatesData(byte[] data)
        {
            var reader = new SshDataReader(data);
            var dataKeyName = reader.ReadString(Encoding.ASCII);
            if (dataKeyName != PublicKeyName)
                throw new CryptographicException($"Key and certificates [{dataKeyName}]"
                    + $" were not created with this algorithm [{PublicKeyName}].");

            var point = reader.ReadBinary();
            _prvKey = null;
            _pubKey = new(point);
        }

        /// <summary>
        /// Signs the data with Ed25519, returning the SSH signature blob.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>The raw SSH signature blob.</returns>
        public override byte[] SignData(byte[] data)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, _prvKey);
            signer.BlockUpdate(data);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Signs a pre-computed hash with Ed25519, returning the SSH signature.
        /// </summary>
        /// <param name="hash">The hash to sign.</param>
        /// <returns>The raw SSH signature blob.</returns>
        public override byte[] SignHash(byte[] hash)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, _prvKey);
            signer.BlockUpdate(hash);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Verifies an Ed25519 signature over the data.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The raw SSH signature blob</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyData(byte[] data, byte[] signature)
        {
            var signer = new Ed25519Signer();
            signer.Init(false, _pubKey);
            signer.BlockUpdate(data);
            return signer.VerifySignature(signature);
        }

        /// <summary>
        /// Verifies an Ed25519 signature over a pre-computed hash.
        /// </summary>
        /// <param name="hash">The signed hash.</param>
        /// <param name="signature">The raw SSH signature blob.</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            var signer = new Ed25519Signer();
            signer.Init(false, _pubKey);
            signer.BlockUpdate(hash);
            return signer.VerifySignature(signature);
        }
    }

}
