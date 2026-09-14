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

        public IEnumerable<string> Keys => _orderedNames;

        public IEnumerable<Func<string, T>> Values => _orderedNames.Select(name => _map[name]);

        public int Count => _orderedNames.Length;

        public Func<string, T> this[string name] => _map[name];

        public bool ContainsKey(string name) => _map.ContainsKey(name);

        public bool TryGetValue(string name, out Func<string, T> value) => _map.TryGetValue(name, out value);

        public IEnumerator<KeyValuePair<string, Func<string, T>>> GetEnumerator() =>
            _orderedNames.Select(name => new KeyValuePair<string, Func<string, T>>(name, _map[name])).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
