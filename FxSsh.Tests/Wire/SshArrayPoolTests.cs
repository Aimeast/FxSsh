using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Wire
{
    [TestClass]
    public sealed class SshArrayPoolTests
    {
        // Fresh pool per test so TLS/shared stack state can't leak between tests.
        private static SshArrayPool CreatePool() => new();

        [TestMethod]
        public void Rent_negative_length_throws()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => CreatePool().Rent(-1));
        }

        [TestMethod]
        public void Rent_returns_power_of_two_bucket_at_least_requested()
        {
            var pool = CreatePool();

            Assert.AreEqual(16, pool.Rent(1).Length);
            Assert.AreEqual(16, pool.Rent(16).Length);
            Assert.AreEqual(32, pool.Rent(17).Length);
            Assert.AreEqual(64 * 1024, pool.Rent(64 * 1024).Length);
        }

        [TestMethod]
        public void Rent_beyond_max_bucket_allocates_exact_size()
        {
            var pool = CreatePool();

            var buffer = pool.Rent(64 * 1024 + 1);

            Assert.AreEqual(64 * 1024 + 1, buffer.Length);
        }

        [TestMethod]
        public void Return_then_Rent_reuses_the_same_buffer()
        {
            var pool = CreatePool();
            var first = pool.Rent(128);
            first[0] = 0xAB;

            pool.Return(first);
            var second = pool.Rent(128);

            Assert.AreSame(first, second);
        }

        [TestMethod]
        public void Return_with_clearArray_zeroes_the_buffer()
        {
            var pool = CreatePool();
            var buffer = pool.Rent(128);
            buffer.AsSpan().Fill(0xAB);

            pool.Return(buffer, clearArray: true);
            var reused = pool.Rent(128);

            Assert.AreSame(buffer, reused);
            Assert.AreEqual(0, reused[0]);
            Assert.AreEqual(0, reused[^1]);
        }

        [TestMethod]
        public void Return_of_non_bucket_size_is_dropped_silently()
        {
            var pool = CreatePool();
            var legitimate = pool.Rent(16);

            // 17 bytes is not a bucket size (and not a power of two): the
            // pool must silently drop it instead of corrupting a bucket.
            pool.Return(new byte[17]);
            pool.Return(new byte[8]);
            pool.Return(new byte[128 * 1024]);

            var next = pool.Rent(16);
            Assert.AreNotSame(legitimate, next);
        }

        [TestMethod]
        public void Return_of_null_throws()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => CreatePool().Return(null!));
        }
    }
}
