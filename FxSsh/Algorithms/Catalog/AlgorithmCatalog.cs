using System;
using System.Collections;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.Algorithms.Catalog
{
    public class AlgorithmSelection
    {
        private AlgorithmCatalog _catalog = new();
        private bool _marked = false;

        public IReadOnlyDictionary<string, Func<string, PublicKeyAlgorithm>> HostKeySelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, KexAlgorithm>> KeyExchangeSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, CipherInfo>> EncryptionSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, HmacInfo>> HmacSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, CompressionAlgorithm>> CompressionSelection { get; private set; }

        public void ConfigureHazmat(Action<AlgorithmCatalog> configure)
        {
            if (_marked)
                throw new InvalidOperationException("ConfigureHazmat may only be called before the server starts.");
            configure(_catalog);
        }

        internal void BuildSelection(Action<AlgorithmCatalog> logger)
        {
            _marked = true;
            logger(_catalog);
            HostKeySelection = _catalog.HostKeyCollection.BuildSelection();
            KeyExchangeSelection = _catalog.KeyExchangeCollection.BuildSelection();
            EncryptionSelection = _catalog.EncryptionCollection.BuildSelection();
            HmacSelection = _catalog.HmacCollection.BuildSelection();
            CompressionSelection = _catalog.CompressionCollection.BuildSelection();
        }
    }

    public class AlgorithmCatalog
    {
        public AlgorithmCollection<PublicKeyAlgorithm> HostKeyCollection = [
            ("ecdsa-sha2-nistp256", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP256)), x => new EcdsaKey("nistp256", x)),
            ("ecdsa-sha2-nistp384", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP384)), x => new EcdsaKey("nistp384", x)),
            ("ecdsa-sha2-nistp521", AlgorithmTag.BuiltIn, TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP521)), x => new EcdsaKey("nistp521", x)),
            ("rsa-sha2-256", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(256, x)),
            ("rsa-sha2-512", AlgorithmTag.BuiltIn, TryCreate(RSA.Create), x => new RsaKey(512, x)),
        ];
        public AlgorithmCollection<KexAlgorithm> KeyExchangeCollection = [
            ("mlkem768x25519-sha256", AlgorithmTag.BuiltIn, MLKem.IsSupported, _ => new MlkemX25519Kex()),
            ("curve25519-sha256", AlgorithmTag.BuiltIn, X25519DiffieHellman.IsSupported, _ => new X25519Kex()),
            ("ecdh-sha2-nistp256", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)), _ => new EcdhKex("nistp256")),
            ("ecdh-sha2-nistp384", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)), _ => new EcdhKex("nistp384")),
            ("ecdh-sha2-nistp521", AlgorithmTag.BuiltIn, TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521)), _ => new EcdhKex("nistp521")),
            ("diffie-hellman-group18-sha512", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(512, 8192)),
            ("diffie-hellman-group16-sha512", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(512, 4096)),
            ("diffie-hellman-group14-sha256", AlgorithmTag.BuiltIn, true, _ => new DiffieHellmanKex(256, 2048)),
        ];
        public AlgorithmCollection<CipherInfo> EncryptionCollection = [
            ("aes256-cbc", AlgorithmTag.Disable, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CBC)),
            ("aes256-ctr", AlgorithmTag.BuiltIn, TryCreate(Aes.Create), _ => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR)),
            ("aes256-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(256)),
            ("aes128-gcm@openssh.com", AlgorithmTag.BuiltIn, AesGcm.IsSupported, _ => new CipherInfo(128)),
        ];
        public AlgorithmCollection<HmacInfo> HmacCollection = [
            ("hmac-sha2-256", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256)),
            ("hmac-sha2-512", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512)),
            ("hmac-sha2-256-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA256(), 256, true)),
            ("hmac-sha2-512-etm@openssh.com", AlgorithmTag.BuiltIn, true, _ => new HmacInfo(new HMACSHA512(), 512, true)),
        ];
        public AlgorithmCollection<CompressionAlgorithm> CompressionCollection = [
            ("none", AlgorithmTag.BuiltIn, true, _ => new NoCompression()),
        ];

        private static bool TryCreate(Func<IDisposable> create)
        {
            try
            {
                using var _ = create();
                return true;
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or CryptographicException)
            {
                return false;
            }
        }
    }

    public enum AlgorithmTag
    {
        Disable,
        BuiltIn,
        Obsolete,
        Alias,
        Custom,
    }

    public record AlgorithmDefine<T>(string Name, AlgorithmTag Tag, bool Supported, Func<string, T> Factory)
    {
        public static implicit operator AlgorithmDefine<T>((string Name, AlgorithmTag Tag, bool Supported, Func<string, T> Factory) t)
            => new(t.Name, t.Tag, t.Supported, t.Factory);
    }

    public class AlgorithmCollection<T> : IEnumerable<AlgorithmDefine<T>>
    {
        private IDictionary<string, AlgorithmDefine<T>> _items = new Dictionary<string, AlgorithmDefine<T>>();

        internal void Add(AlgorithmDefine<T> item) => _items[item.Name] = item;

        internal IReadOnlyDictionary<string, Func<string, T>> BuildSelection() =>
             _items.Where(x => x.Value.Tag != AlgorithmTag.Disable && x.Value.Supported).ToFrozenDictionary(x => x.Key, y => y.Value.Factory);

        public void Add(string name, Func<string, T> factory) => _items[name] = new AlgorithmDefine<T>(name, AlgorithmTag.Custom, true, factory);

        public void AddAlias(string aliasName, string targetName) => _items[aliasName] = _items[targetName] with { Name = aliasName };

        public bool Remove(string name) => _items.Remove(name);

        public void Clear() => _items.Clear();

        public void Enable(string name)
        {
            if (_items[name].Tag == AlgorithmTag.Disable)
                _items[name] = _items[name] with { Tag = AlgorithmTag.Obsolete };
        }

        public IEnumerable<string> Names => _items.Keys;

        public IEnumerator<AlgorithmDefine<T>> GetEnumerator() => _items.Values.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

}
