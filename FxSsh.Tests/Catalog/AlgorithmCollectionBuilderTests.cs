using System;
using System.Collections.Generic;
using System.Linq;
using FxSsh.Algorithms.Catalog;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Catalog
{
    [TestClass]
    public sealed class AlgorithmCollectionBuilderTests
    {
        private static AlgorithmCollectionBuilder<object> CreateBuilder() => new();

        [TestMethod]
        public void Add_appends_in_insertion_order_and_is_negotiable()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            builder.Add("b", _ => new object());

            CollectionAssert.AreEqual(new[] { "a", "b" }, builder.Names.ToArray());
            CollectionAssert.AreEqual(new[] { "a", "b" }, builder.NegotiableNames.ToArray());
        }

        [TestMethod]
        public void Add_existing_name_replaces_in_place()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            builder.Add("b", _ => new object());

            object replacement = new();
            builder.Add("a", _ => replacement);

            CollectionAssert.AreEqual(new[] { "a", "b" }, builder.Names.ToArray());
            Assert.AreSame(replacement, builder.BuildCollection()["a"](null!));
        }

        [TestMethod]
        public void Disable_excludes_from_negotiation_but_keeps_the_entry()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            builder.Add("b", _ => new object());

            builder.Disable("a");

            CollectionAssert.AreEqual(new[] { "a", "b" }, builder.Names.ToArray());
            CollectionAssert.AreEqual(new[] { "b" }, builder.NegotiableNames.ToArray());
            Assert.IsFalse(builder.BuildCollection().ContainsKey("a"));
        }

        [TestMethod]
        public void Disable_unknown_name_throws()
        {
            Assert.ThrowsExactly<KeyNotFoundException>(() => CreateBuilder().Disable("missing"));
        }

        [TestMethod]
        public void Enable_restores_a_disabled_entry_as_negotiable()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            builder.Disable("a");

            builder.Enable("a");

            CollectionAssert.AreEqual(new[] { "a" }, builder.NegotiableNames.ToArray());
            Assert.IsTrue(builder.BuildCollection().ContainsKey("a"));
        }

        [TestMethod]
        public void Enable_unknown_name_throws()
        {
            Assert.ThrowsExactly<KeyNotFoundException>(() => CreateBuilder().Enable("missing"));
        }

        [TestMethod]
        public void Remove_deletes_the_entry()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            builder.Add("b", _ => new object());

            builder.Remove("a");

            CollectionAssert.AreEqual(new[] { "b" }, builder.Names.ToArray());
        }

        [TestMethod]
        public void Remove_unknown_name_throws()
        {
            Assert.ThrowsExactly<KeyNotFoundException>(() => CreateBuilder().Remove("missing"));
        }

        [TestMethod]
        public void Clear_empties_the_collection()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());

            builder.Clear();

            Assert.AreEqual(0, builder.Names.Count());
            Assert.AreEqual(0, builder.BuildCollection().Count);
        }

        [TestMethod]
        public void AddAlias_requires_an_existing_target()
        {
            Assert.ThrowsExactly<KeyNotFoundException>(
                () => CreateBuilder().AddAlias("alias", "missing-target"));
        }

        [TestMethod]
        public void AddAlias_shares_the_target_factory_and_is_negotiable()
        {
            var builder = CreateBuilder();
            object shared = new();
            builder.Add("target", _ => shared);

            builder.AddAlias("alias", "target");

            CollectionAssert.AreEqual(new[] { "target", "alias" }, builder.Names.ToArray());
            CollectionAssert.AreEqual(new[] { "target", "alias" }, builder.NegotiableNames.ToArray());

            // The alias delegates to the target's factory, so both names
            // resolve to instances produced by the same factory.
            var frozen = builder.BuildCollection();
            Assert.AreSame(shared, frozen["target"](null!));
            Assert.AreSame(shared, frozen["alias"](null!));
        }

        [TestMethod]
        public void BuildCollection_excludes_unsupported_entries()
        {
            var builder = CreateBuilder();
            builder.Add(new AlgorithmDefine<object>("supported", AlgorithmTag.BuiltIn, true, _ => new object()));
            builder.Add(new AlgorithmDefine<object>("unsupported", AlgorithmTag.BuiltIn, false, _ => new object()));

            CollectionAssert.AreEqual(new[] { "supported" }, builder.NegotiableNames.ToArray());
            Assert.IsFalse(builder.BuildCollection().ContainsKey("unsupported"));
        }

        [TestMethod]
        public void BuildCollection_is_a_frozen_snapshot()
        {
            var builder = CreateBuilder();
            builder.Add("a", _ => new object());
            var frozen = builder.BuildCollection();

            builder.Disable("a");
            builder.Add("b", _ => new object());

            Assert.IsTrue(frozen.ContainsKey("a"));
            Assert.IsFalse(frozen.ContainsKey("b"));
            Assert.AreEqual(1, frozen.Count);
        }

        [TestMethod]
        public void Factory_receives_the_negotiated_name()
        {
            // RSA/ECDSA key factories branch on the negotiated name
            // (e.g. rsa-sha2-256 vs rsa-sha2-512), so the name handed to the
            // factory is load-bearing.
            var builder = CreateBuilder();
            string? received = null;
            builder.Add("a", name => { received = name; return new object(); });

            builder.BuildCollection()["a"]("a");

            Assert.AreEqual("a", received);
        }
    }
}
