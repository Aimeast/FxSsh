using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace FxSsh
{
    /// <summary>
    /// TLS-first ArrayPool dedicated to SSH packet buffers (16 B - 128 KiB).
    ///
    /// Why not <see cref="ArrayPool{T}.Create()"/>? That returns a
    /// ConfigurableArrayPool whose per-bucket SpinLock serializes every
    /// Rent/Return, which collapsed GCM single-connection throughput when it
    /// was tried during development. Why not <see cref="ArrayPool{T}.Shared"/>?
    /// Shared is already lock-free, but it is global - every other library in
    /// the process competes for the same buckets, and its per-core stacks can
    /// be exhausted under extreme concurrency, degrading into fresh
    /// allocations. This dedicated pool isolates SSH traffic and mirrors the
    /// TlsOverPerCoreLockedStacks design:
    ///
    /// - Per-thread (ThreadStatic) LIFO stack per size bucket: the Session hot
    ///   path's 3 Rent/Return per packet all happen on the same receive/send
    ///   pump thread, so the common case is zero-contention. The stacks are
    ///   bounded by both a per-bucket count and a per-thread byte budget, so a
    ///   thread cannot pin an unbounded amount of pooled memory.
    /// - A bounded shared ConcurrentStack per bucket as the fallback for
    ///   cross-thread rentals (e.g. a buffer rented on the message-loop task
    ///   and returned on a send-pump task). ConcurrentStack is lock-free. The
    ///   shared side is capped by both an entry count and a byte budget per
    ///   bucket, so bursty cross-thread traffic cannot retain close to a
    ///   gigabyte (the old 8192-entry-per-bucket cap allowed that).
    /// - Rent/Return are size-validated; out-of-range buffers are dropped, so
    ///   a stray Return can never corrupt the pool.
    /// </summary>
    internal sealed class SshArrayPool : ArrayPool<byte>
    {
        private const int MinBucketSize = 16;            // 2^4
        private const int MaxBucketSize = 128 * 1024;    // 2^17: covers 64 KiB SFTP responses + framing slack
        private const int NumBuckets = 14;               // 16 .. 131072
        private const int TlsStackCapacity = 16;         // per-thread per-bucket cache
        private const int TlsCacheByteLimit = 256 * 1024; // total per-thread cached bytes
        private const int SharedStackCapacity = 1024;    // per-bucket shared entry cap
        private const int SharedBucketByteLimit = 2 * 1024 * 1024; // per-bucket shared byte cap

        [ThreadStatic]
        private static Stack<byte[]>[] t_tlsStacks;

        // Total bytes currently parked in this thread's stacks. The per-bucket
        // count cap alone allowed up to ~2 MB of pinned buffers per thread
        // (16 arrays in every bucket); this byte budget keeps the fast path
        // for the common small buckets while bounding pool-wide retention.
        [ThreadStatic]
        private static int t_tlsCacheBytes;

        private readonly ConcurrentStack<byte[]>[] _sharedStacks = new ConcurrentStack<byte[]>[NumBuckets];
        private readonly int[] _sharedCounts = new int[NumBuckets];
        private readonly int[] _sharedBytes = new int[NumBuckets];

        public SshArrayPool()
        {
            for (var i = 0; i < NumBuckets; i++)
                _sharedStacks[i] = new ConcurrentStack<byte[]>();
        }

        public override byte[] Rent(int minimumLength)
        {
            if (minimumLength < 0)
                throw new ArgumentOutOfRangeException(nameof(minimumLength));

            if (minimumLength > MaxBucketSize)
                return new byte[minimumLength];   // out of range: allocate, never cached

            var bucket = GetBucketIndex(minimumLength);

            // Fast path: this thread's own stack - no lock, no CAS.
            var tls = t_tlsStacks;
            if (tls != null)
            {
                var stack = tls[bucket];
                if (stack != null && stack.Count > 0)
                {
                    var cached = stack.Pop();
                    t_tlsCacheBytes -= cached.Length;
                    return cached;
                }
            }

            // Cross-thread path: shared stack (lock-free).
            if (_sharedStacks[bucket].TryPop(out var buffer))
            {
                Interlocked.Decrement(ref _sharedCounts[bucket]);
                Interlocked.Add(ref _sharedBytes[bucket], -buffer.Length);
                return buffer;
            }

            return new byte[GetBucketSize(bucket)];
        }

        public override void Return(byte[] array, bool clearArray = false)
        {
            ArgumentNullException.ThrowIfNull(array);

            // Only accept buffers that belong to this pool's bucket sizes.
            if (array.Length < MinBucketSize || array.Length > MaxBucketSize || (array.Length & (array.Length - 1)) != 0)
                return;   // not ours: drop silently rather than corrupt the pool

            if (clearArray)
                Array.Clear(array, 0, array.Length);

            var bucket = GetBucketIndex(array.Length);

            // Fast path: this thread's own stack (bounded).
            var tls = t_tlsStacks;
            if (tls == null)
            {
                tls = new Stack<byte[]>[NumBuckets];
                t_tlsStacks = tls;
            }

            var stack = tls[bucket];
            if (stack == null)
            {
                stack = new Stack<byte[]>(TlsStackCapacity);
                tls[bucket] = stack;
            }

            if (stack.Count < TlsStackCapacity && t_tlsCacheBytes + array.Length <= TlsCacheByteLimit)
            {
                stack.Push(array);
                t_tlsCacheBytes += array.Length;
                return;
            }

            // TLS full: fall back to the bounded shared stack; drop if full to
            // cap memory instead of growing without limit. Both an entry count
            // and a byte budget bound each bucket, so a burst of large buffers
            // cannot pin hundreds of megabytes. Both counters are advanced
            // unconditionally and the rollback undoes exactly those two
            // operations, so a rejected return cannot desynchronise the count
            // from the stack contents.
            var sharedCount = Interlocked.Increment(ref _sharedCounts[bucket]);
            var sharedBytes = Interlocked.Add(ref _sharedBytes[bucket], array.Length);
            if (sharedCount <= SharedStackCapacity && sharedBytes <= SharedBucketByteLimit)
            {
                _sharedStacks[bucket].Push(array);
            }
            else
            {
                Interlocked.Decrement(ref _sharedCounts[bucket]);
                Interlocked.Add(ref _sharedBytes[bucket], -array.Length);
            }
        }

        private static int GetBucketIndex(int size)
        {
            var bucket = 0;
            var s = MinBucketSize;
            while (s < size)
            {
                s <<= 1;
                bucket++;
            }
            return bucket;
        }

        private static int GetBucketSize(int bucket) => MinBucketSize << bucket;
    }

    /// <summary>
    /// Dedicated pool for SSH packet-sized buffers (16 B - 128 KiB), used by
    /// Session's framing hot path, SshDataWriter, HMAC concatenation, the
    /// connection-service data lease and the forwarding bridges. Isolated from
    /// ArrayPool&lt;byte&gt;.Shared so SSH traffic never competes with the rest
    /// of the process for buckets, and TLS-first so the per-packet Rent/Return
    /// on a single thread stays lock-free.
    /// </summary>
    internal static class SshBuffers
    {
        public static readonly ArrayPool<byte> Packets = new SshArrayPool();
    }
}
