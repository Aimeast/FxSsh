using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using FxSsh.Logging;

#nullable enable

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Built-in algorithm suites. The option lists (KeyExchangeAlgorithms,
    /// HostKeyAlgorithms, EncryptionAlgorithms, MacAlgorithms,
    /// CompressionAlgorithms) are the algorithms selectable on the current
    /// platform, in priority order; each catalog entry probes its own support
    /// once at static initialization. Assign a subset of a list to an
    /// AlgorithmSelection to limit a server to those algorithms; null means
    /// "all supported".
    /// </summary>
    public static class AlgorithmRegistry
    {
        // Field declaration order matters: the catalogs must be initialized
        // before the option lists, which are derived from them.

        private static readonly (string Name, Func<KexAlgorithm> Factory, bool Supported)[] KeyExchangeCatalog =
        [
            ("mlkem768x25519-sha256", () => new MlkemX25519Kex(), TryCreate(() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768))),
            ("curve25519-sha256", () => new X25519Kex(), TryCreate(() => X25519DiffieHellman.GenerateKey())),
            ("ecdh-sha2-nistp256", () => new EcdhKex("nistp256"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))),
            ("ecdh-sha2-nistp384", () => new EcdhKex("nistp384"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384))),
            ("ecdh-sha2-nistp521", () => new EcdhKex("nistp521"), TryCreate(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521))),
            ("diffie-hellman-group18-sha512", () => new DiffieHellmanKex(512, 8192), true),
            ("diffie-hellman-group16-sha512", () => new DiffieHellmanKex(512, 4096), true),
            ("diffie-hellman-group14-sha256", () => new DiffieHellmanKex(256, 2048), true),
        ];

        private static readonly (string Name, Func<string, PublicKeyAlgorithm> Factory, bool Supported)[] HostKeyCatalog =
        [
            ("ecdsa-sha2-nistp256", x => new EcdsaKey("nistp256", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP256))),
            ("ecdsa-sha2-nistp384", x => new EcdsaKey("nistp384", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP384))),
            ("ecdsa-sha2-nistp521", x => new EcdsaKey("nistp521", x), TryCreate(() => ECDsa.Create(ECCurve.NamedCurves.nistP521))),
            ("rsa-sha2-256", x => new RsaKey(256, x), TryCreate(() => RSA.Create())),
            ("rsa-sha2-512", x => new RsaKey(512, x), TryCreate(() => RSA.Create())),
        ];

        private static readonly (string Name, Func<CipherInfo> Factory, bool Supported)[] EncryptionCatalog =
        [
            ("aes256-ctr", () => new CipherInfo(Aes.Create(), 256, CipherModeEx.CTR), TryCreate(() => Aes.Create())),
            ("aes256-gcm@openssh.com", () => new CipherInfo(256), AesGcm.IsSupported),
            ("aes128-gcm@openssh.com", () => new CipherInfo(128), AesGcm.IsSupported),
        ];

        private static readonly (string Name, Func<HmacInfo> Factory, bool Supported)[] MacCatalog =
        [
            ("hmac-sha2-256", () => new HmacInfo(new HMACSHA256(), 256), true),
            ("hmac-sha2-512", () => new HmacInfo(new HMACSHA512(), 512), true),
            ("hmac-sha2-256-etm@openssh.com", () => new HmacInfo(new HMACSHA256(), 256, true), true),
            ("hmac-sha2-512-etm@openssh.com", () => new HmacInfo(new HMACSHA512(), 512, true), true),
        ];

        private static readonly (string Name, Func<CompressionAlgorithm> Factory, bool Supported)[] CompressionCatalog =
        [
            ("none", () => new NoCompression(), true),
        ];

        // --- Selectable option lists (filtered to what this platform supports) ---

        /// <summary>Key exchange algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> KeyExchangeAlgorithms = SupportedNames(KeyExchangeCatalog);

        /// <summary>Host key / signature algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> HostKeyAlgorithms = SupportedNames(HostKeyCatalog);

        /// <summary>Encryption (cipher) algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> EncryptionAlgorithms = SupportedNames(EncryptionCatalog);

        /// <summary>MAC algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> MacAlgorithms = SupportedNames(MacCatalog);

        /// <summary>Compression algorithms selectable on this platform, in priority order.</summary>
        public static readonly IReadOnlyList<string> CompressionAlgorithms = SupportedNames(CompressionCatalog);

        // Obsolete built-ins (revivable via HazmatAlgorithmList.Enable). Their
        // factories are supplied here so Enable/AddAlias can reference them as
        // built-in names. aes256-cbc / 3des-cbc are not implemented (stubs throw)
        // per the project's "no new algorithms in core" policy; curve25519-sha256@libssh.org
        // reuses the existing X25519 key exchange.

        internal static readonly (string Name, Func<KexAlgorithm> Factory)[] ObsoleteKeyExchange =
        [
            ("curve25519-sha256@libssh.org", () => new X25519Kex()),
        ];

        internal static readonly (string Name, Func<CipherInfo> Factory)[] ObsoleteEncryption =
        [
            ("aes256-cbc", () => throw new NotSupportedException("aes256-cbc is not implemented in the core library.")),
            ("3des-cbc", () => throw new NotSupportedException("3des-cbc is not implemented in the core library.")),
        ];

        // --- Resolution: null selector = all supported, list = subset by name ---

        internal static Dictionary<string, Func<KexAlgorithm>> ResolveKeyExchange(IReadOnlyList<string>? selected)
            => Resolve(KeyExchangeCatalog, selected, "key exchange");

        internal static Dictionary<string, Func<string, PublicKeyAlgorithm>> ResolveHostKey(IReadOnlyList<string>? selected)
            => Resolve(HostKeyCatalog, selected, "host key");

        internal static Dictionary<string, Func<CipherInfo>> ResolveEncryption(IReadOnlyList<string>? selected)
            => Resolve(EncryptionCatalog, selected, "encryption");

        internal static Dictionary<string, Func<HmacInfo>> ResolveMac(IReadOnlyList<string>? selected)
            => Resolve(MacCatalog, selected, "MAC");

        internal static Dictionary<string, Func<CompressionAlgorithm>> ResolveCompression(IReadOnlyList<string>? selected)
            => Resolve(CompressionCatalog, selected, "compression");

        // Selects the catalog entries for the given names (or every supported
        // algorithm when no selector is set), skips unknown and unsupported
        // names with a warning, and throws when nothing is left.
        private static Dictionary<string, TValue> Resolve<TValue>(
            (string Name, TValue Factory, bool Supported)[] catalog,
            IReadOnlyList<string>? selected,
            string category)
        {
            var result = new Dictionary<string, TValue>();

            if (selected == null)
            {
                foreach (var entry in catalog)
                    if (entry.Supported)
                        result[entry.Name] = entry.Factory;
            }
            else
            {
                foreach (var name in selected)
                {
                    var entry = Array.Find(catalog, e => e.Name == name);
                    if (entry.Name == null)
                    {
                        Log.Warn($"Unknown {category} algorithm '{name}' - skipped.");
                        continue;
                    }
                    if (!entry.Supported)
                    {
                        Log.Warn($"{category} algorithm '{entry.Name}' is not supported on this platform - skipped.");
                        continue;
                    }
                    result[name] = entry.Factory;
                }
            }

            if (result.Count == 0)
                throw new InvalidOperationException($"No supported {category} algorithms configured.");

            return result;
        }

        private static IReadOnlyList<string> SupportedNames<TValue>((string Name, TValue Factory, bool Supported)[] catalog)
            => catalog.Where(e => e.Supported).Select(e => e.Name).ToArray();

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

    /// <summary>
    /// The lifecycle state of an algorithm entry in a
    /// <see cref="HazmatAlgorithmList{TFactory}"/>.
    /// </summary>
    public enum HazmatAlgorithmTag
    {
        /// <summary>A core algorithm shipped and reviewed by the library.</summary>
        BuiltIn,

        /// <summary>An algorithm registered by the application via <c>Add</c>.</summary>
        Custom,

        /// <summary>A second name for a built-in, introduced via <c>AddAlias</c>.</summary>
        Alias,

        /// <summary>A built-in algorithm that is weakly-configured by default and revivable via <c>Enable</c>.</summary>
        Obsolete,
    }

    /// <summary>
    /// A named, ordered collection of algorithm factories for one category of the
    /// server's algorithm registry. Readable at any time (Count, Contains,
    /// enumeration) but only mutable through a <see cref="HazmatAlgorithmCatalog"/>
    /// handed to <see cref="AlgorithmSelection.ConfigureHazmat"/>. The list is
    /// seeded with the platform's supported built-ins; entries may be added,
    /// aliased, enabled, removed, or cleared via the catalog.
    /// </summary>
    public sealed class HazmatAlgorithmList<TFactory> : IEnumerable<KeyValuePair<string, TFactory>>
    {
        private readonly List<Entry> _entries = [];
        private readonly HashSet<string> _builtInNames;
        private readonly Dictionary<string, (TFactory Factory, bool Obsolete)> _builtIn;
        private readonly string _category;
        private bool _writeScope;

        private sealed class Entry
        {
            public required string Name;
            public required TFactory Factory;
            public required HazmatAlgorithmTag Tag;
        }

        internal HazmatAlgorithmList(
            string category,
            IEnumerable<KeyValuePair<string, TFactory>> activeBuiltIns,
            IEnumerable<(string Name, TFactory Factory)> obsoleteBuiltIns)
        {
            _category = category;
            _builtIn = new Dictionary<string, (TFactory Factory, bool Obsolete)>();
            foreach (var kv in activeBuiltIns)
                _builtIn[kv.Key] = (kv.Value, false);
            foreach (var (name, factory) in obsoleteBuiltIns)
                _builtIn[name] = (factory, true);
            _builtInNames = new HashSet<string>(_builtIn.Keys, StringComparer.Ordinal);

            foreach (var kv in activeBuiltIns)
                _entries.Add(new Entry { Name = kv.Key, Factory = kv.Value, Tag = HazmatAlgorithmTag.BuiltIn });
        }

        /// <summary>The number of entries currently in the list.</summary>
        public int Count => _entries.Count;

        /// <summary>True if an algorithm is registered under the given name.</summary>
        public bool Contains(string name) => _entries.Any(e => e.Name == name);

        /// <summary>
        /// Register or replace a factory under a name. The entry is tagged
        /// <see cref="HazmatAlgorithmTag.Custom"/> (replacing keeps any existing
        /// position). Only valid inside <see cref="AlgorithmSelection.ConfigureHazmat"/>.
        /// </summary>
        public void Add(string name, TFactory factory)
        {
            EnsureWriteScope();
            ArgumentNullException.ThrowIfNull(name);
            ArgumentNullException.ThrowIfNull(factory);
            EnsureValidName(name);

            var existing = _entries.FirstOrDefault(e => e.Name == name);
            if (existing != null)
            {
                // Replace in place, keeping the entry's position/order.
                existing.Factory = factory;
                existing.Tag = HazmatAlgorithmTag.Custom;
                existing.Name = name;
                return;
            }

            _entries.Add(new Entry { Name = name, Factory = factory, Tag = HazmatAlgorithmTag.Custom });
        }

        /// <summary>
        /// Add a second name for a built-in, reusing its factory directly. The
        /// alias is placed immediately after its target. Aliasing an obsolete
        /// built-in implicitly enables that target and inherits the Obsolete tag.
        /// Only valid inside <see cref="AlgorithmSelection.ConfigureHazmat"/>.
        /// </summary>
        /// <exception cref="KeyNotFoundException">The target is not a built-in name.</exception>
        public void AddAlias(string aliasName, string targetName)
        {
            EnsureWriteScope();
            ArgumentNullException.ThrowIfNull(aliasName);
            ArgumentNullException.ThrowIfNull(targetName);
            EnsureValidName(aliasName);

            if (!_builtIn.TryGetValue(targetName, out var target))
                throw new KeyNotFoundException($"AddAlias target '{targetName}' is not a known {_category} built-in.");

            // Remove any existing entry under the alias name first.
            _entries.RemoveAll(e => e.Name == aliasName);

            var severity = target.Obsolete ? HazmatAlgorithmTag.Obsolete : HazmatAlgorithmTag.BuiltIn;

            // If an alias targets an (enabled) obsolete built-in, that built-in
            // is already present; otherwise if it's disabled we append it so the
            // alias has a concrete adjacent target ("implicitly enables it").
            if (target.Obsolete && !Contains(targetName))
            {
                _entries.Add(new Entry { Name = targetName, Factory = target.Factory, Tag = HazmatAlgorithmTag.Obsolete });
            }

            var targetIndex = _entries.FindIndex(e => e.Name == targetName);
            _entries.Insert(targetIndex + 1, new Entry { Name = aliasName, Factory = target.Factory, Tag = severity });
        }

        /// <summary>
        /// Remove an entry by name. Returns false (without throwing) if the name
        /// is absent. The null/obsolete built-ins stay in the built-in inventory so
        /// they can be re-added or aliased later. Only valid inside
        /// <see cref="AlgorithmSelection.ConfigureHazmat"/>.
        /// </summary>
        public bool Remove(string name)
        {
            EnsureWriteScope();
            ArgumentNullException.ThrowIfNull(name);
            return _entries.RemoveAll(e => e.Name == name) > 0;
        }

        /// <summary>
        /// Remove every entry (the escape hatch for full reordering). The built-in
        /// inventory is unaffected, so <see cref="Add"/> can re-add them in any order.
        /// Only valid inside <see cref="AlgorithmSelection.ConfigureHazmat"/>.
        /// </summary>
        public void Clear()
        {
            EnsureWriteScope();
            _entries.Clear();
        }

        /// <summary>
        /// Revive one obsolete built-in, appending it at the end of the category
        /// with the <see cref="HazmatAlgorithmTag.Obsolete"/> tag.
        /// Only valid inside <see cref="AlgorithmSelection.ConfigureHazmat"/>.
        /// </summary>
        /// <exception cref="KeyNotFoundException">The name is not a known obsolete built-in.</exception>
        /// <exception cref="InvalidOperationException">The algorithm is not an obsolete built-in or is already enabled.</exception>
        public void Enable(string name)
        {
            EnsureWriteScope();
            ArgumentNullException.ThrowIfNull(name);

            if (!_builtIn.TryGetValue(name, out var entry) || !entry.Obsolete)
                throw new KeyNotFoundException($"'{name}' is not an obsolete {_category} built-in that can be enabled.");

            if (Contains(name))
                throw new InvalidOperationException($"Obsolete {_category} algorithm '{name}' is already enabled.");

            _entries.Add(new Entry { Name = name, Factory = entry.Factory, Tag = HazmatAlgorithmTag.Obsolete });
        }

        // --- Internal reads used by the library and the hazmat catalog ---

        internal IEnumerable<(string Name, TFactory Factory, HazmatAlgorithmTag Tag)> TaggedEntries
            => _entries.Select(e => (e.Name, e.Factory, e.Tag));

        internal void OpenWriteScope() => _writeScope = true;
        internal void CloseWriteScope() => _writeScope = false;

        public IEnumerator<KeyValuePair<string, TFactory>> GetEnumerator()
            => _entries.Select(e => new KeyValuePair<string, TFactory>(e.Name, e.Factory)).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private void EnsureWriteScope()
        {
            if (!_writeScope)
                throw new InvalidOperationException(
                    "HazmatAlgorithmList may only be mutated inside the AlgorithmSelection.ConfigureHazmat callback.");
        }

        private static readonly Regex SshAlgorithmName = new(@"^[A-Za-z0-9]([A-Za-z0-9\-._@]*[A-Za-z0-9@])?$", RegexOptions.Compiled);

        private static void EnsureValidName(string name)
        {
            if (!SshAlgorithmName.IsMatch(name))
                throw new InvalidOperationException($"Algorithm name '{name}' does not match the SSH algorithm-name grammar.");
        }
    }

    /// <summary>
    /// Mutable view of the server's algorithm registry, handed only to
    /// <see cref="AlgorithmSelection.ConfigureHazmat"/>. The object is valid only
    /// inside the callback; capturing it (or any of its lists) for later mutation
    /// throws. Named "HazMat" to signal that mutating the advertised algorithm
    /// set is an expert-only operation that bypasses the built-in security story.
    /// </summary>
    public sealed class HazmatAlgorithmCatalog
    {
        internal HazmatAlgorithmCatalog(
            HazmatAlgorithmList<Func<KexAlgorithm>> keyExchange,
            HazmatAlgorithmList<Func<string, PublicKeyAlgorithm>> publicKey,
            HazmatAlgorithmList<Func<CipherInfo>> encryption,
            HazmatAlgorithmList<Func<HmacInfo>> hmac,
            HazmatAlgorithmList<Func<CompressionAlgorithm>> compression)
        {
            KeyExchange = keyExchange;
            PublicKey = publicKey;
            Encryption = encryption;
            Hmac = hmac;
            Compression = compression;
        }

        /// <summary>Key exchange algorithms, in server preference order.</summary>
        public HazmatAlgorithmList<Func<KexAlgorithm>> KeyExchange { get; }

        /// <summary>Host key / signature algorithms, in server preference order.</summary>
        public HazmatAlgorithmList<Func<string, PublicKeyAlgorithm>> PublicKey { get; }

        /// <summary>Encryption (cipher) algorithms, in server preference order.</summary>
        public HazmatAlgorithmList<Func<CipherInfo>> Encryption { get; }

        /// <summary>MAC algorithms, in server preference order.</summary>
        public HazmatAlgorithmList<Func<HmacInfo>> Hmac { get; }

        /// <summary>Compression algorithms, in server preference order.</summary>
        public HazmatAlgorithmList<Func<CompressionAlgorithm>> Compression { get; }
    }

    /// <summary>
    /// Per-server algorithm selection. Each selector is null by default, meaning
    /// "use every algorithm in the corresponding registry", and may be assigned a
    /// subset of the matching <see cref="AlgorithmRegistry"/> option list to
    /// restrict that category. A server (or session) may additionally register
    /// custom/legacy algorithms via <see cref="ConfigureHazmat"/> before it starts.
    /// </summary>
    public sealed class AlgorithmSelection
    {
        private readonly HazmatAlgorithmList<Func<KexAlgorithm>> _keyExchange;
        private readonly HazmatAlgorithmList<Func<string, PublicKeyAlgorithm>> _publicKey;
        private readonly HazmatAlgorithmList<Func<CipherInfo>> _encryption;
        private readonly HazmatAlgorithmList<Func<HmacInfo>> _hmac;
        private readonly HazmatAlgorithmList<Func<CompressionAlgorithm>> _compression;

        private bool _started;
        private bool _hazmatConfigured;

        public AlgorithmSelection()
        {
            // Null selectors resolve to every algorithm supported on this
            // platform, matching upstream's default.
            _keyExchange = new HazmatAlgorithmList<Func<KexAlgorithm>>(
                "key exchange",
                AlgorithmRegistry.ResolveKeyExchange(null),
                AlgorithmRegistry.ObsoleteKeyExchange);
            _publicKey = new HazmatAlgorithmList<Func<string, PublicKeyAlgorithm>>(
                "host key",
                AlgorithmRegistry.ResolveHostKey(null),
                []);
            _encryption = new HazmatAlgorithmList<Func<CipherInfo>>(
                "encryption",
                AlgorithmRegistry.ResolveEncryption(null),
                AlgorithmRegistry.ObsoleteEncryption);
            _hmac = new HazmatAlgorithmList<Func<HmacInfo>>(
                "MAC",
                AlgorithmRegistry.ResolveMac(null),
                []);
            _compression = new HazmatAlgorithmList<Func<CompressionAlgorithm>>(
                "compression",
                AlgorithmRegistry.ResolveCompression(null),
                []);
        }

        /// <summary>Key exchange selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? KeyExchangeAlgorithms { get; set; }

        /// <summary>Host key selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? HostKeyAlgorithms { get; set; }

        /// <summary>Encryption (cipher) selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? EncryptionAlgorithms { get; set; }

        /// <summary>MAC selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? MacAlgorithms { get; set; }

        /// <summary>Compression selector; null = all supported defaults.</summary>
        public IReadOnlyList<string>? CompressionAlgorithms { get; set; }

        /// <summary>True once <see cref="ConfigureHazmat"/> has been invoked.</summary>
        public bool IsHazmatConfigured => _hazmatConfigured;

        /// <summary>
        /// The only way to mutate the algorithm registry after construction, and
        /// therefore the only way to plug in custom or legacy algorithms. May be
        /// called multiple times before the server starts (calls compose in order);
        /// throws afterwards. The callback receives a
        /// <see cref="HazmatAlgorithmCatalog"/> valid only for the duration of the
        /// callback; capturing the catalog (or any of its lists) for later use or
        /// mutation throws.
        /// </summary>
        public void ConfigureHazmat(Action<HazmatAlgorithmCatalog> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);
            if (_started)
                throw new InvalidOperationException("ConfigureHazmat may only be called before the server starts.");

            // Snapshot the current names for use in the config-time diff logging.
            var before = Snapshot();

            var catalog = new HazmatAlgorithmCatalog(_keyExchange, _publicKey, _encryption, _hmac, _compression);
            _keyExchange.OpenWriteScope();
            _publicKey.OpenWriteScope();
            _encryption.OpenWriteScope();
            _hmac.OpenWriteScope();
            _compression.OpenWriteScope();
            try
            {
                configure(catalog);
            }
            finally
            {
                _keyExchange.CloseWriteScope();
                _publicKey.CloseWriteScope();
                _encryption.CloseWriteScope();
                _hmac.CloseWriteScope();
                _compression.CloseWriteScope();
            }

            // Fail-fast validation at the callback boundary: factory nullability
            // and grammar are enforced per-mutation; uniqueness is re-checked here
            // because Alias/Replace operations could otherwise produce a duplicate.
            EnsureUnique(_keyExchange, "key exchange");
            EnsureUnique(_publicKey, "host key");
            EnsureUnique(_encryption, "encryption");
            EnsureUnique(_hmac, "MAC");
            EnsureUnique(_compression, "compression");

            LogConfigDiff(before);

            _hazmatConfigured = true;
        }

        internal void MarkStarted() => _started = true;

        // --- Read access for the library internals (Session / SshServer). These
        // are deliberately not public - consumers configure through the selectors
        // and ConfigureHazmat only. Each resolves the selector filter against the
        // (mutable) registry and yields tag-aware entries so negotiation can log
        // warnings for Custom/Obsolete algorithms.

        internal IReadOnlyList<(string Name, TFactory Factory, HazmatAlgorithmTag Tag)> Resolve<TFactory>(
            HazmatAlgorithmList<TFactory> list, IReadOnlyList<string>? selected, string category)
        {
            if (selected == null)
                return list.TaggedEntries.ToArray();

            var entries = list.TaggedEntries.ToList();
            var result = new List<(string Name, TFactory Factory, HazmatAlgorithmTag Tag)>();
            foreach (var name in selected)
            {
                var found = entries.FirstOrDefault(e => e.Name == name);
                if (found.Name == null)
                {
                    Log.Warn($"Unknown {category} algorithm '{name}' - skipped.");
                    continue;
                }
                result.Add(found);
            }

            if (result.Count == 0)
                throw new InvalidOperationException($"No supported {category} algorithms configured.");

            return result;
        }

        internal IReadOnlyList<(string Name, Func<KexAlgorithm> Factory, HazmatAlgorithmTag Tag)> KeyExchange
            => Resolve(_keyExchange, KeyExchangeAlgorithms, "key exchange");

        internal IReadOnlyList<(string Name, Func<string, PublicKeyAlgorithm> Factory, HazmatAlgorithmTag Tag)> PublicKey
            => Resolve(_publicKey, HostKeyAlgorithms, "host key");

        internal IReadOnlyList<(string Name, Func<CipherInfo> Factory, HazmatAlgorithmTag Tag)> Encryption
            => Resolve(_encryption, EncryptionAlgorithms, "encryption");

        internal IReadOnlyList<(string Name, Func<HmacInfo> Factory, HazmatAlgorithmTag Tag)> Hmac
            => Resolve(_hmac, MacAlgorithms, "MAC");

        internal IReadOnlyList<(string Name, Func<CompressionAlgorithm> Factory, HazmatAlgorithmTag Tag)> Compression
            => Resolve(_compression, CompressionAlgorithms, "compression");

        private Dictionary<string, (string Name, HazmatAlgorithmTag Tag)[]> Snapshot()
        {
            return new Dictionary<string, (string Name, HazmatAlgorithmTag Tag)[]>
            {
                ["key exchange"] = _keyExchange.TaggedEntries.Select(e => (e.Name, e.Tag)).ToArray(),
                ["host key"] = _publicKey.TaggedEntries.Select(e => (e.Name, e.Tag)).ToArray(),
                ["encryption"] = _encryption.TaggedEntries.Select(e => (e.Name, e.Tag)).ToArray(),
                ["MAC"] = _hmac.TaggedEntries.Select(e => (e.Name, e.Tag)).ToArray(),
                ["compression"] = _compression.TaggedEntries.Select(e => (e.Name, e.Tag)).ToArray(),
            };
        }

        private static void EnsureUnique<TFactory>(HazmatAlgorithmList<TFactory> list, string category)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var e in list.TaggedEntries)
                if (!seen.Add(e.Name))
                    throw new InvalidOperationException(
                        $"Duplicate {category} algorithm name '{e.Name}' after ConfigureHazmat.");
        }

        private void LogConfigDiff(Dictionary<string, (string Name, HazmatAlgorithmTag Tag)[]> before)
        {
            LogDiff("key exchange", before, _keyExchange);
            LogDiff("host key", before, _publicKey);
            LogDiff("encryption", before, _encryption);
            LogDiff("MAC", before, _hmac);
            LogDiff("compression", before, _compression);
        }

        private static void LogDiff<TFactory>(string category,
            Dictionary<string, (string Name, HazmatAlgorithmTag Tag)[]> before,
            HazmatAlgorithmList<TFactory> list)
        {
            if (!Log.IsEnabled(LogLevel.Info))
                return;

            var prior = before.TryGetValue(category, out var p) ? p : [];
            var priorNames = new HashSet<string>(prior.Select(x => x.Name), StringComparer.Ordinal);
            var afterNames = new HashSet<string>(list.TaggedEntries.Select(e => e.Name), StringComparer.Ordinal);

            var added = list.TaggedEntries.Where(e => !priorNames.Contains(e.Name)).ToArray();
            var removed = prior.Where(x => !afterNames.Contains(x.Name)).ToArray();

            var parts = new List<string>();
            foreach (var e in added)
            {
                var label = e.Tag switch
                {
                    HazmatAlgorithmTag.Custom => "custom",
                    HazmatAlgorithmTag.Alias => "alias",
                    HazmatAlgorithmTag.Obsolete => "obsolete",
                    _ => "added",
                };
                parts.Add($"{e.Name} ({label})");
            }
            foreach (var r in removed)
                parts.Add($"-{r.Name}");

            if (parts.Count > 0 && Log.IsEnabled(LogLevel.Info))
                Log.Info($"ConfigureHazmat {category} diff: {string.Join(", ", parts)}.");
        }
    }
}
