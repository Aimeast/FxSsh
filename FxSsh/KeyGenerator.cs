using System;
using System.Security.Cryptography;

namespace FxSsh
{
    /// <summary>
    /// Provides helpers for generating host keys in PEM form and converting
    /// legacy RSA key blobs, as accepted by
    /// <see cref="SshServer.AddHostKey(string, string)"/>.
    /// </summary>
    public static class KeyGenerator
    {
        /// <summary>
        /// Generates a new RSA private key and exports it in PKCS#8 PEM
        /// format.
        /// </summary>
        /// <param name="bitlen">The key size in bits. Must be 2048, 4096, or 8192.</param>
        /// <returns>The PKCS#8 PEM representation of the new private key.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="bitlen"/> is not 2048, 4096, or 8192.
        /// </exception>
        public static string GenerateRsaKeyPem(int bitlen)
        {
            if (bitlen != 2048 && bitlen != 4096 && bitlen != 8192)
                throw new ArgumentOutOfRangeException(nameof(bitlen), bitlen, "Bit length must be 2048, 4096 or 8192.");

            var rsa = RSA.Create(bitlen);
            return rsa.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Generates a new ECDSA private key on a named NIST curve and exports
        /// it in PKCS#8 PEM format.
        /// </summary>
        /// <param name="curveName">
        /// The curve name. Must be "nistp256", "nistp384", or "nistp521".
        /// </param>
        /// <returns>The PKCS#8 PEM representation of the new private key.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="curveName"/> is not one of the supported curve
        /// names.
        /// </exception>
        public static string GenerateECDsaKeyPem(string curveName)
        {
            if (curveName != "nistp256" && curveName != "nistp384" && curveName != "nistp521")
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, "Curve name must be nistp256, nistp384 or nistp521.");

            var curve = default(ECCurve);
            if (curveName == "nistp256") curve = ECCurve.NamedCurves.nistP256;
            else if (curveName == "nistp384") curve = ECCurve.NamedCurves.nistP384;
            else if (curveName == "nistp521") curve = ECCurve.NamedCurves.nistP521;
            var ecdsa = ECDsa.Create(curve);
            return ecdsa.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Converts a legacy RSA key stored as a base64-encoded cryptographic
        /// service provider (CSP) blob to PKCS#8 PEM format.
        /// </summary>
        /// <param name="oldBase64Key">The base64-encoded CSP blob of the RSA key.</param>
        /// <returns>The PKCS#8 PEM representation of the imported key.</returns>
        public static string ConvertRsaBase64KeyToPem(string oldBase64Key)
        {
            ArgumentNullException.ThrowIfNull(oldBase64Key);

            var rsa = new RSACryptoServiceProvider();
            var bytes = Convert.FromBase64String(oldBase64Key);
            rsa.ImportCspBlob(bytes);
            var pem = rsa.ExportPkcs8PrivateKeyPem();
            return pem;
        }
    }
}
