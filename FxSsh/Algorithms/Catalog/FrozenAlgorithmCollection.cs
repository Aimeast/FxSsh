using System;
using System.Collections;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;

namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// Immutable snapshot of one algorithm category: a name → factory lookup
    /// that enumerates in the builder's configuration order.
    /// </summary>
    /// <remarks>
    /// The enumeration order of <see cref="Keys"/> is the algorithm preference
    /// order advertised in the KEXINIT name-lists, where the first mutually
    /// supported entry wins negotiation - so order is part of the contract.
    /// A FrozenDictionary alone would not preserve it, hence the ordered
    /// name list beside the O(1) lookup map.
    /// </remarks>
    public sealed class FrozenAlgorithmCollection<T> : IReadOnlyDictionary<string, Func<string, T>>
    {
        private readonly FrozenDictionary<string, Func<string, T>> _map;
        private readonly string[] _orderedNames;

        internal FrozenAlgorithmCollection(KeyValuePair<string, Func<string, T>>[] entries)
        {
            _map = entries.ToFrozenDictionary();
            _orderedNames = entries.Select(x => x.Key).ToArray();
        }

        /// <summary>
        /// Gets the entry names in preference order - the exact order the
        /// KEXINIT name-lists advertise.
        /// </summary>
        public IEnumerable<string> Keys => _orderedNames;

        /// <summary>
        /// Gets the entry factories in the same preference order as
        /// <see cref="Keys"/>.
        /// </summary>
        public IEnumerable<Func<string, T>> Values => _orderedNames.Select(name => _map[name]);

        /// <summary>Gets the number of entries in the collection.</summary>
        public int Count => _orderedNames.Length;

        /// <summary>
        /// Gets the factory registered under <paramref name="name"/>.
        /// </summary>
        /// <param name="name">The algorithm name, e.g. "aes256-ctr".</param>
        /// <returns>The factory that builds the per-direction algorithm instance.</returns>
        /// <exception cref="KeyNotFoundException">No entry is registered under <paramref name="name"/>.</exception>
        public Func<string, T> this[string name] => _map[name];

        /// <summary>
        /// Determines whether an entry is registered under
        /// <paramref name="name"/>.
        /// </summary>
        /// <param name="name">The algorithm name to look up.</param>
        /// <returns>True when an entry exists under <paramref name="name"/>; otherwise false.</returns>
        public bool ContainsKey(string name) => _map.ContainsKey(name);

        /// <summary>
        /// Gets the factory registered under <paramref name="name"/>.
        /// </summary>
        /// <param name="name">The algorithm name to look up.</param>
        /// <param name="value">Receives the factory when the lookup succeeds; otherwise the default value.</param>
        /// <returns>True when an entry exists under <paramref name="name"/>; otherwise false.</returns>
        public bool TryGetValue(string name, out Func<string, T> value) => _map.TryGetValue(name, out value);

        /// <summary>
        /// Returns an enumerator over the entries in preference order.
        /// </summary>
        /// <returns>An enumerator of name/factory pairs.</returns>
        public IEnumerator<KeyValuePair<string, Func<string, T>>> GetEnumerator() =>
            _orderedNames.Select(name => new KeyValuePair<string, Func<string, T>>(name, _map[name])).GetEnumerator();

        /// <summary>
        /// Returns an enumerator over the entries in preference order.
        /// </summary>
        /// <returns>An enumerator of name/factory pairs.</returns>
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
