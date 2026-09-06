using System;
using System.Collections.Generic;

namespace FxSsh.Algorithms.Catalog
{
    public class AlgorithmSelection
    {
        private readonly AlgorithmCatalog _catalog = new();
        private bool _built = false;

        public IReadOnlyDictionary<string, Func<string, PublicKeyAlgorithm>> HostKeySelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, KexAlgorithm>> KeyExchangeSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, CipherInfo>> EncryptionSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, HmacInfo>> HmacSelection { get; private set; }
        public IReadOnlyDictionary<string, Func<string, CompressionAlgorithm>> CompressionSelection { get; private set; }

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
        /// Idempotent: a later call (e.g. after a Stop/Start cycle) reuses the
        /// frozen snapshot instead of rebuilding.
        /// </summary>
        internal void BuildSelection(Action<AlgorithmCatalog> logger)
        {
            if (_built)
                return;
            _built = true;
            logger(_catalog);
            HostKeySelection = _catalog.HostKeyCollection.BuildCollection();
            KeyExchangeSelection = _catalog.KeyExchangeCollection.BuildCollection();
            EncryptionSelection = _catalog.EncryptionCollection.BuildCollection();
            HmacSelection = _catalog.HmacCollection.BuildCollection();
            CompressionSelection = _catalog.CompressionCollection.BuildCollection();
        }
    }
}
