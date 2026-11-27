using System;
using FxSsh.Services;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    [TestClass]
    public sealed class ChannelDataLeaseTests
    {
        [TestMethod]
        public void Wrapped_lease_copies_for_a_consumer()
        {
            var source = new byte[] { 1, 2, 3 };
            var lease = ChannelDataLease.Wrap(source);

            Assert.IsFalse(lease.TryRetainOrCopy(out var owned));
            Assert.AreNotSame(lease, owned);
            CollectionAssert.AreEqual(source, owned.Memory.ToArray());

            lease.ReleaseIfNotRetained();
            owned.Dispose();
        }

        [TestMethod]
        public void Owning_lease_transfers_ownership_once()
        {
            var source = new byte[] { 4, 5, 6 };
            var lease = ChannelDataLease.CopyFrom(source);

            Assert.IsTrue(lease.TryRetainOrCopy(out var first));
            Assert.AreSame(lease, first);

            // The dispatcher must not release a lease a consumer retained.
            lease.ReleaseIfNotRetained();
            CollectionAssert.AreEqual(source, first.Memory.ToArray());

            first.Dispose();
            Assert.ThrowsExactly<ObjectDisposedException>(() => first.Memory.ToArray());
        }

        [TestMethod]
        public void Second_consumer_gets_an_independent_copy()
        {
            var source = new byte[] { 7, 8, 9 };
            var lease = ChannelDataLease.CopyFrom(source);

            Assert.IsTrue(lease.TryRetainOrCopy(out var first));
            Assert.IsFalse(lease.TryRetainOrCopy(out var second));
            Assert.AreNotSame(lease, second);

            CollectionAssert.AreEqual(source, second.Memory.ToArray());
            first.Dispose();
            second.Dispose();
        }
    }
}
