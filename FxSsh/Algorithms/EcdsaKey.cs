using System;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// The ECDSA host key algorithm over the NIST curves (RFC 5656),
    /// producing ecdsa-sha2-nistp256/nistp384/nistp521 signatures.
    /// Keys are stored as PKCS#8/PEM; signatures are converted between
    /// the SSH (r,s) mpint blob and IEEE P1363 concatenation form.
    /// </summary>
    public class EcdsaKey : PublicKeyAlgorithm
    {
        private readonly ECDsa _algorithm = ECDsa.Create();
        private readonly HashAlgorithmName _sha;
        private readonly string _curveName;

        /// <summary>
        /// Initializes a new instance of the <see cref="EcdsaKey"/> class,
        /// generating a key on the named curve when none is supplied.
        /// </summary>
        /// <param name="curveName">The NIST curve: "nistp256", "nistp384" or "nistp521".</param>
        /// <param name="key">The key in PEM format, or an empty string to generate a new key.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="curveName"/> is not a supported NIST curve.</exception>
        public EcdsaKey(string curveName, string key)
            : base(key)
        {
            if (curveName != "nistp256" && curveName != "nistp384" && curveName != "nistp521")
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, "Curve name must be nistp256, nistp384 or nistp521.");

            _curveName = curveName;
            var noKey = string.IsNullOrEmpty(key);
            if (curveName == "nistp256")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                _sha = HashAlgorithmName.SHA256;
            }
            else if (curveName == "nistp384")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                _sha = HashAlgorithmName.SHA384;
            }
            else if (curveName == "nistp521")
            {
                if (noKey) _algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP521);
                _sha = HashAlgorithmName.SHA512;
            }
        }

        /// <summary>
        /// Gets the algorithm name, "ecdsa-sha2-" followed by the curve name
        /// (RFC 5656 section 6.2), e.g. "ecdsa-sha2-nistp256".
        /// </summary>
        public override string Name
        {
            get { return $"ecdsa-sha2-{_curveName}"; }
        }

        /// <summary>
        /// Imports a PEM-encoded key (PKCS#8 private key or SPKI public key).
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
        /// Loads an ECDSA public key from its SSH wire blob: the algorithm
        /// name and curve name strings followed by the uncompressed EC point
        /// Q (0x04 || X || Y), per RFC 5656 section 3.1.
        /// </summary>
        /// <param name="data">The key blob.</param>
        /// <exception cref="CryptographicException">The blob names a different algorithm or uses a compressed curve point.</exception>
        public override void LoadKeyAndCertificatesData(byte[] data)
        {
            var reader = new SshDataReader(data);
            if (reader.ReadString(Encoding.ASCII) != this.Name
                || reader.ReadString(Encoding.ASCII) != _curveName)
                throw new CryptographicException("Key and certificates were not created with this algorithm.");

            var bytesQ = reader.ReadBinaryAsMemory();
            var readerQ = new SshDataReader(bytesQ);
            if (readerQ.ReadByte() != 0x04)
                throw new CryptographicException("Curve point compression is not supported.");
            var fieldSize = bytesQ.Length / 2;
            var args = _algorithm.ExportParameters(false);
            args.Q.X = readerQ.ReadBytes(fieldSize);
            args.Q.Y = readerQ.ReadBytes(fieldSize);

            _algorithm.ImportParameters(args);
        }

        /// <summary>
        /// Serializes the public key to the SSH wire blob: the algorithm and
        /// curve name strings followed by the uncompressed EC point Q,
        /// per RFC 5656 section 3.1.
        /// </summary>
        /// <returns>The key blob.</returns>
        public override byte[] CreateKeyAndCertificatesData()
        {
            var args = _algorithm.ExportParameters(false);
            var bytesQ = new SshDataWriter(1 + args.Q.X.Length + args.Q.Y.Length)
                .Write(0x04)
                .WriteBytes(args.Q.X)
                .WriteBytes(args.Q.Y)
                .ToByteArray();
            return new SshDataWriter(12 + this.Name.Length + _curveName.Length + bytesQ.Length)
                .Write(this.Name, Encoding.ASCII)
                .Write(_curveName, Encoding.ASCII)
                .WriteBinary(bytesQ)
                .ToByteArray();
        }

        /// <summary>
        /// Verifies an ECDSA signature over the data. The SSH (r,s) blob is
        /// converted to IEEE P1363 form before verification.
        /// </summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The raw SSH signature blob (r and s as mpint).</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyData(byte[] data, byte[] signature)
        {
            var sig = SignatureBlobToP1363(signature);
            return _algorithm.VerifyData(data, sig, _sha, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        /// <summary>
        /// Verifies an ECDSA signature over a pre-computed hash.
        /// </summary>
        /// <param name="hash">The signed hash.</param>
        /// <param name="signature">The raw SSH signature blob (r and s as mpint).</param>
        /// <returns>true when the signature is valid; otherwise false.</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            var sig = SignatureBlobToP1363(signature);
            return _algorithm.VerifyHash(hash, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        private byte[] SignatureBlobToP1363(byte[] signatureBlob)
        {
            var reader = new SshDataReader(signatureBlob);
            var r = reader.ReadMpint();
            var s = reader.ReadMpint();
            var fieldSize = (_algorithm.KeySize + 7) >> 3;
            // equal to (int)Math.Ceiling((double)_algorithm.KeySize / 8);
            //_algorithm.KeySize == 256 ? 32 :
            //_algorithm.KeySize == 384 ? 48 :
            //_algorithm.KeySize == 521 ? 66 :
            //throw new InvalidDataException();
            var bytes = new byte[fieldSize * 2];
            Array.Copy(r, 0, bytes, fieldSize - r.Length, r.Length);
            Array.Copy(s, 0, bytes, fieldSize + fieldSize - s.Length, s.Length);
            return bytes;
        }

        /// <summary>
        /// Signs the data with ECDSA, returning the SSH signature blob
        /// (r and s as mpint values, RFC 5656 section 3.1.2).
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <returns>The raw SSH signature blob.</returns>
        public override byte[] SignData(byte[] data)
        {
            var sig = _algorithm.SignData(data, _sha, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return P1363ToSignatureBlob(sig);
        }

        /// <summary>
        /// Signs a pre-computed hash with ECDSA, returning the SSH signature
        /// blob (r and s as mpint values).
        /// </summary>
        /// <param name="hash">The hash to sign.</param>
        /// <returns>The raw SSH signature blob.</returns>
        public override byte[] SignHash(byte[] hash)
        {
            var sig = _algorithm.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return P1363ToSignatureBlob(sig);
        }

        private byte[] P1363ToSignatureBlob(byte[] p1363Bytes)
        {
            var fieldSize = p1363Bytes.Length / 2;
            var bytes = p1363Bytes.AsMemory();
            return new SshDataWriter(8 + p1363Bytes.Length)
                .WriteMpint(bytes[..fieldSize])
                .WriteMpint(bytes[fieldSize..])
                .ToByteArray();
        }
    }
}
