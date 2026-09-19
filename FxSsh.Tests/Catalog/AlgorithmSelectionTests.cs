using System;
using System.Linq;
using FxSsh.Algorithms.Catalog;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Catalog
{
    [TestClass]
    public sealed class AlgorithmSelectionTests
    {
        [TestMethod]
        public void ConfigureHazmat_rejects_null()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new AlgorithmSelection().ConfigureHazmat(null!));
        }

        [TestMethod]
        public void ConfigureHazmat_applies_changes_before_build()
        {
            var selection = new AlgorithmSelection();

            selection.ConfigureHazmat(catalog => catalog.EncryptionCollection.Disable("aes256-ctr"));
            selection.BuildSelection(null);

            Assert.IsFalse(selection.EncryptionSelection.ContainsKey("aes256-ctr"));
        }

        [TestMethod]
        public void ConfigureHazmat_after_build_throws()
        {
            var selection = new AlgorithmSelection();
            selection.BuildSelection(null);

            Assert.ThrowsExactly<InvalidOperationException>(
                () => selection.ConfigureHazmat(_ => { }));
        }

        [TestMethod]
        public void BuildSelection_is_idempotent()
        {
            var selection = new AlgorithmSelection();
            var built = false;

            selection.BuildSelection(_ => built = true);
            selection.BuildSelection(_ => built = true);

            Assert.IsTrue(built);
            Assert.IsNotNull(selection.HostKeySelection);
            Assert.IsNotNull(selection.KeyExchangeSelection);
            Assert.IsNotNull(selection.EncryptionSelection);
            Assert.IsNotNull(selection.HmacSelection);
            Assert.IsNotNull(selection.CompressionSelection);
        }

        [TestMethod]
        public void BuildSelection_freezes_the_configured_state()
        {
            var selection = new AlgorithmSelection();
            var countBefore = 0;

            selection.ConfigureHazmat(catalog => countBefore = catalog.HostKeyCollection.NegotiableNames.Count());
            selection.BuildSelection(null);

            Assert.AreEqual(countBefore, selection.HostKeySelection.Count);
        }

        [TestMethod]
        public void BuildSelection_invokes_the_callback_with_the_catalog()
        {
            var selection = new AlgorithmSelection();
            AlgorithmCatalog? observed = null;

            selection.BuildSelection(catalog => observed = catalog);

            Assert.IsNotNull(observed);
        }
    }
}
