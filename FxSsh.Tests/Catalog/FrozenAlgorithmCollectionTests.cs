using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Algorithms.Catalog;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Catalog
{
    [TestClass]
    public sealed class FrozenAlgorithmCollectionTests
    {
        private static FrozenAlgorithmCollection<object> Create(params string[] names) =>
            new(names.Select(n => new KeyValuePair<string, Func<string, object>>(n, _ => new object())).ToArray());

        [TestMethod]
        public void Keys_preserve_the_entry_order()
        {
            var collection = Create("z-alg", "a-alg", "m-alg");

            // Order is the SSH negotiation preference - iteration must not be
            // re-sorted (e.g. alphabetically) by the frozen dictionary.
            CollectionAssert.AreEqual(new[] { "z-alg", "a-alg", "m-alg" }, collection.Keys.ToArray());
            CollectionAssert.AreEqual(new[] { "z-alg", "a-alg", "m-alg" }, collection.Select(kv => kv.Key).ToArray());
        }

        [TestMethod]
        public void Values_follow_the_key_order()
        {
            var collection = Create("first", "second");

            Assert.AreEqual(2, collection.Values.Count());
        }

        [TestMethod]
        public void Count_and_ContainsKey_reflect_the_entries()
        {
            var collection = Create("a", "b");

            Assert.AreEqual(2, collection.Count);
            Assert.IsTrue(collection.ContainsKey("a"));
            Assert.IsFalse(collection.ContainsKey("missing"));
        }

        [TestMethod]
        public void Indexer_and_TryGetValue_resolve_factories()
        {
            var collection = Create("a");

            Assert.IsNotNull(collection["a"]);
            Assert.IsTrue(collection.TryGetValue("a", out var viaTry));
            Assert.IsNotNull(viaTry);
            Assert.IsFalse(collection.TryGetValue("missing", out var nothing));
            Assert.IsNull(nothing);
        }

        [TestMethod]
        public void Indexer_of_unknown_name_throws()
        {
            Assert.ThrowsExactly<KeyNotFoundException>(() => _ = Create("a")["missing"]);
        }
    }
}
