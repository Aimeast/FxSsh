using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// The seeded per-server algorithm catalog. Entries are listed in
    /// preference order, which the KEXINIT name-lists advertise as-is;
    /// customize through <see cref="AlgorithmSelection.ConfigureHazmat"/>
    /// before the server starts.
    /// </summary>
    public class AlgorithmCatalog
    {
        public AlgorithmCollectionBuilder<PublicKeyAlgorithm> HostKeyCollection { get; } = [
            ("ecdsa-sha2-nistp256", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP256)), x => new EcdsaKey("nistp256", x)),
            ("ecdsa-sha2-nistp384", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP384)), x => new EcdsaKey("nistp384", x)),
            ("ecdsa-sha2-nistp521", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP521)), x => new EcdsaKey("nistp521", x)),
            ("rsa-sha2-256", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(256, x)),
            ("rsa-sha2-512", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(512, x)),
        ];
        public AlgorithmCollectionBuilder<KexAlgorithm> KeyExchangeCollection { get; } = [
            ("mlkem768x25519-sha256", AlgorithmTag.BuiltIn, MLKem.IsSupported, _ => new MlkemX25519Kex()),
            ("curve25519-sha256", AlgorithmTag.BuiltIn, X25519DiffieHellman.IsSupported, _ => new X25519Kex()),
            ("ecdh-sha2-nistp256", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)), _ => new EcdhKex("nistp256")),
            ("ecdh-sha2-nistp384", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)), _ => new EcdhKex("nistp384")),
            ("ecdh-sha2-nistp521", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521)), _ => new EcdhKex("nistp521")),
            ("diffie-hellman-group18-sha512", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(512, 8192)),
            ("diffie-hellman-group16-sha512", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(512, 4096)),
            ("diffie-hellman-group14-sha256", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(256, 2048)),
        ];
        public AlgorithmCollectionBuilder<CipherInfo> EncryptionCollection { get; } = [
            ("aes256-cbc", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CBC)),
            ("aes256-ctr", AlgorithmTag.BuiltIn, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR)),
            ("aes256-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(256)),
            ("aes128-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(128)),
        ];
        // Encrypt-then-MAC variants first: with ordered negotiation they are
        // the preferred choice whenever the peer lists them at all.
        public AlgorithmCollectionBuilder<HmacInfo> HmacCollection { get; } = [
            ("hmac-sha2-256-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256, true)),
            ("hmac-sha2-512-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512, true)),
            ("hmac-sha2-256", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256)),
            ("hmac-sha2-512", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512)),
        ];
        public AlgorithmCollectionBuilder<CompressionAlgorithm> CompressionCollection { get; } = [
            ("none", AlgorithmTag.BuiltIn, true, _ => new NoCompression()),
        ];

        private static bool TryCreate(Func<IDisposable> create)
        {
            try
            {
                using var probed = create();
                return true;
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or CryptographicException or InvalidOperationException)
            {
                return false;
            }
        }
    }
}
