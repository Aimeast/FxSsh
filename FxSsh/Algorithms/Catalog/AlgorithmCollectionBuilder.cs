using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace FxSsh.Algorithms.Catalog
{
    /// <summary>
    /// Mutable, order-preserving builder for one algorithm category. Entries
    /// are enumerated in configuration order, which becomes the algorithm
    /// preference order once frozen. Freeze it with <see cref="BuildCollection"/>
    /// when configuration completes; the resulting
    /// <see cref="FrozenAlgorithmCollection{T}"/> is what negotiation consumes.
    /// </summary>
    public sealed class AlgorithmCollectionBuilder<T> : IEnumerable<AlgorithmDefine<T>>
    {
        // A list with a linear name scan (categories hold a handful of
        // entries) keeps the configured order intact across every mutation;
        // a Dictionary would only preserve insertion order incidentally, and
        // FrozenDictionary's iteration order is unspecified - both unacceptable
        // for SSH name-lists, where order is the negotiation preference.
        private readonly List<AlgorithmDefine<T>> _items = [];

        /// <summary>
        /// Adds an entry, or replaces an existing entry with the same name in
        /// place (keeping its position). Used by collection initializers.
        /// </summary>
        internal void Add(AlgorithmDefine<T> item)
        {
            var index = IndexOf(item.Name);
            if (index >= 0)
                _items[index] = item;
            else
                _items.Add(item);
        }

        /// <summary>
        /// Registers a user-contributed algorithm. It participates in
        /// negotiation (subject to <paramref name="name"/> ordering) and is
        /// reported by the startup "custom algorithms" log.
        /// </summary>
        public void Add(string name, Func<string, T> factory) =>
            Add(new AlgorithmDefine<T>(name, AlgorithmTag.Custom, true, factory));

        /// <summary>
        /// Registers <paramref name="aliasName"/> as another name for the
        /// existing <paramref name="targetName"/> entry, tagged
        /// <see cref="AlgorithmTag.Alias"/>.
        /// </summary>
        /// <remarks>
        /// The alias snapshots the target's definition at creation time:
        /// later Enable/Disable/Remove calls on the target do not affect it.
        /// </remarks>
        public void AddAlias(string aliasName, string targetName)
        {
            var index = IndexOf(targetName);
            if (index < 0)
                throw new KeyNotFoundException($"Alias target '{targetName}' was not found in the collection.");
            _items.Add(_items[index] with { Name = aliasName, Tag = AlgorithmTag.Alias });
        }

        /// <summary>
        /// Excludes an entry from negotiation without deleting it, tagging it
        /// <see cref="AlgorithmTag.Disable"/>. Returns false when
        /// <paramref name="name"/> is unknown.
        /// </summary>
        public bool Disable(string name)
        {
            var index = IndexOf(name);
            if (index < 0)
                return false;
            _items[index] = _items[index] with { Tag = AlgorithmTag.Disable };
            return true;
        }

        /// <summary>
        /// Re-enables an entry seeded as <see cref="AlgorithmTag.Disable"/>
        /// (a legacy algorithm kept out of negotiation by default): the entry
        /// becomes negotiable, tagged <see cref="AlgorithmTag.Obsolete"/> so
        /// the startup log warns about it. Throws when
        /// <paramref name="name"/> is unknown.
        /// </summary>
        public void Enable(string name)
        {
            var index = IndexOf(name);
            if (index < 0)
                throw new KeyNotFoundException($"Algorithm '{name}' was not found in the collection.");
            if (_items[index].Tag == AlgorithmTag.Disable)
                _items[index] = _items[index] with { Tag = AlgorithmTag.Obsolete };
        }

        public bool Remove(string name)
        {
            var index = IndexOf(name);
            if (index < 0)
                return false;
            _items.RemoveAt(index);
            return true;
        }

        public void Clear() => _items.Clear();

        public IEnumerable<string> Names => _items.Select(x => x.Name);

        /// <summary>
        /// Freezes the builder into a read-only snapshot. Entries tagged
        /// <see cref="AlgorithmTag.Disable"/> and entries whose platform probe
        /// failed are excluded; the surviving entries keep their configured
        /// order, which the KEXINIT name-lists advertise as preference order.
        /// </summary>
        public FrozenAlgorithmCollection<T> BuildCollection() =>
            new(_items
                .Where(x => x.Tag != AlgorithmTag.Disable && x.Supported)
                .Select(x => new KeyValuePair<string, Func<string, T>>(x.Name, x.Factory))
                .ToArray());

        private int IndexOf(string name)
        {
            for (var i = 0; i < _items.Count; i++)
                if (string.Equals(_items[i].Name, name, StringComparison.Ordinal))
                    return i;
            return -1;
        }

        public IEnumerator<AlgorithmDefine<T>> GetEnumerator() => _items.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
