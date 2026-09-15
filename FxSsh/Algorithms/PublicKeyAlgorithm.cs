using System;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Base class for SSH public key algorithms (RFC 4253 section 6.6),
    /// such as ssh-rsa and ecdsa-sha2-nistp256. Implements the SSH signature
    /// blob framing (algorithm name + signature wire format) and delegates
    /// the actual key storage and signing to the derived class.
    /// </summary>
    public abstract class PublicKeyAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyAlgorithm"/> class,
        /// importing an existing key when one is supplied.
        /// </summary>
        /// <param name="key">The key in SSH public key or PEM format, or an empty string to start without a key.</param>
        public PublicKeyAlgorithm(string key)
        {
            if (!string.IsNullOrEmpty(key))
                ImportKey(key);
        }

        /// <summary>
        /// Gets the SSH protocol name of the algorithm, e.g. "ssh-rsa".
        /// </summary>
        public abstract string Name { get; }

        /// <summary>
        /// Gets the name used to identify the public key on the wire, which
        /// differs from <see cref="Name"/> only for certificate formats.
        /// </summary>
        public virtual string PublicKeyName { get { return Name; } }

        /// <summary>
        /// Computes the Base64-encoded SHA-256 fingerprint of the public key blob.
        /// </summary>
        /// <returns>The fingerprint of the key, Base64 encoded.</returns>
        public string GetFingerprint()
        {
            var bytes = SHA256.HashData(CreateKeyAndCertificatesData());
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Extracts the raw signature from an SSH signature blob, verifying
        /// that it was produced with this algorithm.
        /// </summary>
        /// <param name="signatureData">The SSH signature blob: algorithm name and signature, per RFC 4253 section 6.6.</param>
        /// <returns>The raw signature bytes without the algorithm name framing.</returns>
        /// <exception cref="CryptographicException">The blob names a different algorithm.</exception>
        public byte[] GetSignature(ReadOnlyMemory<byte> signatureData)
        {
            var reader = new SshDataReader(signatureData);
            if (reader.ReadString(Encoding.ASCII) != this.Name)
                throw new CryptographicException("Signature was not created with this algorithm.");

            var signature = reader.ReadBinary();
            return signature;
        }

        /// <summary>
        /// Wraps a raw signature in the SSH signature blob format:
        /// the algorithm name followed by the signature as a binary string.
        /// </summary>
        /// <param name="data">The raw signature bytes produced by <see cref="SignData(byte[])"/>.</param>
        /// <returns>The framed SSH signature blob.</returns>
        public byte[] CreateSignatureData(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            return new SshDataWriter()
                .Write(this.Name, Encoding.ASCII)
                .WriteBinary(SignData(data))
                .ToByteArray();
        }

        /// <summary>
        /// Imports a key in SSH public key or PEM format, replacing any key
        /// held by this instance.
        /// </summary>
        /// <param name="key">The key to import.</param>
        public abstract void ImportKey(string key);

        /// <summary>
        /// Exports the current key in PEM format.
        /// </summary>
        /// <returns>The PEM-encoded key.</returns>
        public abstract string ExportKey();

        /// <summary>
        /// Loads a public key (and certificate, when present) from its SSH wire format.
        /// </summary>
        /// <param name="data">The key blob as carried in an SSH_MSG_USERAUTH_REQUEST or KEX reply.</param>
        public abstract void LoadKeyAndCertificatesData(byte[] data);

        /// <summary>
        /// Serializes the public key (and certificate, when present) to SSH wire format.
        /// </summary>
        /// <returns>The key blob as carried on the wire.</returns>
        public abstract byte[] CreateKeyAndCertificatesData();

        /// <summary>
        /// Verifies a signature over the given data.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The signature framed as an SSH signature blob.</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public abstract bool VerifyData(byte[] data, byte[] signature);

        /// <summary>
        /// Verifies a signature over the given hash.
        /// </summary>
        /// <param name="hash">The signed hash.</param>
        /// <param name="signature">The signature framed as an SSH signature blob.</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public abstract bool VerifyHash(byte[] hash, byte[] signature);

        /// <summary>
        /// Signs the given data with the private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>The raw signature, without SSH framing.</returns>
        public abstract byte[] SignData(byte[] data);

        /// <summary>
        /// Signs the given hash with the private key.
        /// </summary>
        /// <param name="hash">The hash to sign.</param>
        /// <returns>The raw signature, without SSH framing.</returns>
        public abstract byte[] SignHash(byte[] hash);
    }
}
