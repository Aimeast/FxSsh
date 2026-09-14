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
        private bool _built = false;

        public FrozenAlgorithmCollection<PublicKeyAlgorithm> HostKeySelection { get; private set; }
        public FrozenAlgorithmCollection<KexAlgorithm> KeyExchangeSelection { get; private set; }
        public FrozenAlgorithmCollection<CipherInfo> EncryptionSelection { get; private set; }
        public FrozenAlgorithmCollection<HmacInfo> HmacSelection { get; private set; }
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
        /// Configuration and BuildSelection are expected to run on a single
        /// thread (server setup); no synchronization is provided.
        /// </remarks>
        public void ConfigureHazmat(Action<AlgorithmCatalog> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            if (_built)
                throw new InvalidOperationException("ConfigureHazmat may only be called before the server starts.");
            configure(_catalog);
        }

        /// <summary>
        /// Freezes the catalog into the read-only per-category selections.
        /// Idempotent: a later call (e.g. after a Stop/Start cycle, or from
        /// Session's constructor) reuses the frozen snapshot instead of
        /// rebuilding.
        /// </summary>
        internal void BuildSelection(Action<AlgorithmCatalog> logger)
        {
            if (_built)
                return;
            _built = true;
            logger?.Invoke(_catalog);
            HostKeySelection = _catalog.HostKeyCollection.BuildCollection();
            KeyExchangeSelection = _catalog.KeyExchangeCollection.BuildCollection();
            EncryptionSelection = _catalog.EncryptionCollection.BuildCollection();
            HmacSelection = _catalog.HmacCollection.BuildCollection();
            CompressionSelection = _catalog.CompressionCollection.BuildCollection();
        }
    }
}
