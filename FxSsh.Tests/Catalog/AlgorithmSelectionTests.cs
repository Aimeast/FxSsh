using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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

        [TestMethod]
        public async Task BuildSelection_is_serialized_and_fully_initialized()
        {
            var selection = new AlgorithmSelection();
            var loggerEntered = new ManualResetEventSlim();
            var release = new ManualResetEventSlim();
            var calls = 0;

            var first = Task.Run(() => selection.BuildSelection(_ =>
            {
                Interlocked.Increment(ref calls);
                loggerEntered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
            }));
            Assert.IsTrue(loggerEntered.Wait(TimeSpan.FromSeconds(5)), "the first build never started");

            var concurrent = Enumerable.Range(0, 8)
                .Select(_ => Task.Run(() => selection.BuildSelection(_ => Interlocked.Increment(ref calls))))
                .ToArray();
            await Task.Delay(150);
            Assert.IsFalse(concurrent.Any(task => task.IsCompleted),
                "BuildSelection must block while another build is freezing the catalog");

            release.Set();
            await Task.WhenAll(concurrent.Append(first)).WaitAsync(TimeSpan.FromSeconds(10));

            // Only the first call runs the build; the rest observe the frozen
            // snapshot. A half-initialized selection would have null entries.
            Assert.AreEqual(1, calls);
            Assert.IsNotNull(selection.HostKeySelection);
            Assert.IsNotNull(selection.KeyExchangeSelection);
            Assert.IsNotNull(selection.EncryptionSelection);
            Assert.IsNotNull(selection.HmacSelection);
            Assert.IsNotNull(selection.CompressionSelection);
        }
    }
}
