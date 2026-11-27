using FxSsh.Algorithms;

namespace FxSsh
{
    /// <summary>
    /// Provides helpers for generating host keys in PEM form and converting
    /// legacy RSA key blobs, as accepted by
    /// <see cref="SshServer.AddHostKey(string, string)"/>.
    /// </summary>
    public static class Ed25519KeyGeneratorExtensions
    {
        extension(KeyGenerator)
        {
            /// <summary>
            /// Generates a new Ed25519 private key and exports it in PKCS#8 PEM
            /// format.
            /// </summary>
            /// <returns>The PKCS#8 PEM representation of the new private key.</returns>
            public static string GenerateEd25519KeyPem()
            {
                return Ed25519Key.GeneratePrivateKeyPem();
            }
        }
    }
}
