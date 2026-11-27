using System;
using System.Collections.Generic;

namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// The frozen per-category algorithm selections a server negotiates with.
    /// Each property is a name → factory lookup whose <c>Keys</c> enumerates
    /// in the configured preference order - the exact order advertised in the
    /// KEXINIT name-lists - so the enumeration order is part of the contract,
    /// not an implementation detail.
    /// </summary>
    public class AlgorithmSelection
    {
        private readonly AlgorithmCatalog _catalog = new();
        private readonly object _buildLocker = new();
        private bool _built = false;

        /// <summary>
        /// Gets the frozen host key (server signature) algorithms, enumerated
        /// in configured preference order; null until the selection is built
        /// at server start.
        /// </summary>
        public FrozenAlgorithmCollection<PublicKeyAlgorithm> HostKeySelection { get; private set; }

        /// <summary>
        /// Gets the frozen key exchange algorithms, enumerated in configured
        /// preference order; null until the selection is built at server start.
        /// </summary>
        public FrozenAlgorithmCollection<KexAlgorithm> KeyExchangeSelection { get; private set; }

        /// <summary>
        /// Gets the frozen encryption (cipher) algorithms, enumerated in
        /// configured preference order; null until the selection is built at
        /// server start.
        /// </summary>
        public FrozenAlgorithmCollection<CipherInfo> EncryptionSelection { get; private set; }

        /// <summary>
        /// Gets the frozen MAC algorithms, enumerated in configured preference
        /// order; null until the selection is built at server start.
        /// </summary>
        public FrozenAlgorithmCollection<HmacInfo> HmacSelection { get; private set; }

        /// <summary>
        /// Gets the frozen compression methods, enumerated in configured
        /// preference order; null until the selection is built at server start.
        /// </summary>
        public FrozenAlgorithmCollection<CompressionAlgorithm> CompressionSelection { get; private set; }

        /// <summary>
        /// Customizes the per-server algorithm catalog. May only be called
        /// before the server starts; afterwards it throws.
        /// </summary>
        /// <remarks>
        /// This is a configuration convenience, not a security boundary: the
        /// mutable catalog is handed to the callback, so a caller that kept
        /// the reference could still mutate it before the catalog is frozen
        /// at server start. Do not retain the catalog beyond the callback.
        /// Configuration and BuildSelection are serialized; the callback must
        /// not re-enter this selection (for example by calling
        /// BuildSelection), since that would deadlock on the same lock.
        /// </remarks>
        public void ConfigureHazmat(Action<AlgorithmCatalog> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            lock (_buildLocker)
            {
                if (_built)
                    throw new InvalidOperationException("ConfigureHazmat may only be called before the server starts.");
                configure(_catalog);
            }
        }

        /// <summary>
        /// Freezes the catalog into the read-only per-category selections.
        /// Idempotent: a later call (e.g. after a Stop/Start cycle, or from
        /// Session's constructor) reuses the frozen snapshot instead of
        /// rebuilding.
        /// </summary>
        internal void BuildSelection(Action<AlgorithmCatalog> logger)
        {
            lock (_buildLocker)
            {
                if (_built)
                    return;

                logger?.Invoke(_catalog);

                // Build every category into locals first: if any BuildCollection
                // fails, the selection is not marked built and a retry (or the
                // next Start) sees a fully initialized object instead of a
                // half-frozen one with null selections.
                var hostKey = _catalog.HostKeyCollection.BuildCollection();
                var keyExchange = _catalog.KeyExchangeCollection.BuildCollection();
                var encryption = _catalog.EncryptionCollection.BuildCollection();
                var hmac = _catalog.HmacCollection.BuildCollection();
                var compression = _catalog.CompressionCollection.BuildCollection();

                HostKeySelection = hostKey;
                KeyExchangeSelection = keyExchange;
                EncryptionSelection = encryption;
                HmacSelection = hmac;
                CompressionSelection = compression;
                _built = true;
            }
        }
    }
}
