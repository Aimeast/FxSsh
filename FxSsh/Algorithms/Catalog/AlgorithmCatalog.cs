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
        /// <summary>
        /// Seeded host key (server signature) algorithms in preference order:
        /// ECDSA over the nistp256/nistp384/nistp521 curves (RFC 5656), then
        /// rsa-sha2-256 and rsa-sha2-512 (RFC 8332). Entries whose key type is
        /// unavailable on the current platform are excluded when the catalog
        /// is frozen (see <see cref="AlgorithmCollectionBuilder{T}.BuildCollection"/>).
        /// </summary>
        public AlgorithmCollectionBuilder<PublicKeyAlgorithm> HostKeyCollection { get; } = [
            ("ecdsa-sha2-nistp256", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP256)), x => new EcdsaKey("nistp256", x)),
            ("ecdsa-sha2-nistp384", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP384)), x => new EcdsaKey("nistp384", x)),
            ("ecdsa-sha2-nistp521", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP521)), x => new EcdsaKey("nistp521", x)),
            ("rsa-sha2-256", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(256, x)),
            ("rsa-sha2-512", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(512, x)),
        ];
        /// <summary>
        /// Seeded key exchange algorithms in preference order: the hybrid
        /// post-quantum mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex),
        /// curve25519-sha256 (RFC 8731), ecdh-sha2-nistp256/384/521 (RFC 5656),
        /// then the MODP groups diffie-hellman-group18-sha512,
        /// -group16-sha512 and -group14-sha256 (RFC 3526 groups, RFC 8268 SSH
        /// names). Entries whose primitive is unsupported on the current
        /// platform or fails the creation probe are excluded when the catalog
        /// is frozen.
        /// </summary>
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
        /// <summary>
        /// Seeded encryption algorithms in preference order: aes256-ctr (RFC
        /// 4344) and the AES-GCM ciphers (RFC 5647) first, then the legacy
        /// fallbacks (aes192-ctr, aes128-ctr, the AES-CBC variants and
        /// 3des-cbc) seeded as <see cref="AlgorithmTag.Disable"/> so they stay
        /// out of negotiation; <see cref="AlgorithmCollectionBuilder{T}.Enable(string)"/>
        /// re-enables an entry at this seeded tail position, below every
        /// modern cipher.
        /// </summary>
        public AlgorithmCollectionBuilder<CipherInfo> EncryptionCollection { get; } = [
            ("aes256-ctr", AlgorithmTag.BuiltIn, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR)),
            ("aes256-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(256)),
            ("aes128-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(128)),
            // Legacy fallbacks for old peers, seeded as Disable so they stay
            // out of negotiation; Enable() re-enables an entry at this tail
            // position, below every modern cipher.
            ("aes192-ctr", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 192, CipherModeEx.CTR)),
            ("aes128-ctr", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 128, CipherModeEx.CTR)),
            ("aes256-cbc", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CBC)),
            ("aes192-cbc", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 192, CipherModeEx.CBC)),
            ("aes128-cbc", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 128, CipherModeEx.CBC)),
            ("3des-cbc", AlgorithmTag.Disable, TryCreate(TripleDES.Create), _ => new CipherInfo(TripleDES.Create(), 192, CipherModeEx.CBC)),
        ];
        // Encrypt-then-MAC variants first: with ordered negotiation they are
        // the preferred choice whenever the peer lists them at all.
        /// <summary>
        /// Seeded MAC algorithms in preference order, the Encrypt-then-MAC
        /// variants (OpenSSH EtM extension, draft-miller-secsh-etm) first:
        /// with ordered negotiation they win whenever the peer lists them at
        /// all. hmac-sha1 is seeded as
        /// <see cref="AlgorithmTag.Disable"/> and only enters negotiation
        /// after <see cref="AlgorithmCollectionBuilder{T}.Enable(string)"/>.
        /// </summary>
        public AlgorithmCollectionBuilder<HmacInfo> HmacCollection { get; } = [
            ("hmac-sha2-256-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256, true)),
            ("hmac-sha2-512-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512, true)),
            ("hmac-sha2-256", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256)),
            ("hmac-sha2-512", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512)),
            ("hmac-sha1", AlgorithmTag.Disable, true, _ => new HmacInfo(new HMACSHA1(), 160)),
        ];
        /// <summary>
        /// Seeded with only the "none" algorithm, which negotiates whenever
        /// the peer also offers it; compression methods such as zlib can be
        /// registered with
        /// <see cref="AlgorithmCollectionBuilder{T}.Add(string, System.Func{string, T})"/>.
        /// </summary>
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
