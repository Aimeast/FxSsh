using System.Buffers;

namespace FxSsh
{
    /// <summary>
    /// Dedicated ArrayPool for SSH packet-sized buffers (up to 64 KiB).
    ///
    /// The shared <see cref="ArrayPool{byte}.Shared"/> has bounded per-bucket
    /// capacity; at extreme concurrency (n=500, millions of rentals/sec) it
    /// degrades into allocating fresh arrays once the buckets are drained,
    /// and those arrays can then promote into Gen1/Gen2. A dedicated pool
    /// with a large per-bucket allowance keeps packet buffers circulating
    /// between Rent/Return instead of hitting the GC, and isolates SSH
    /// traffic from unrelated Shared users.
    /// </summary>
    internal static class SshBuffers
    {
        /// <summary>
        /// Pool for packet framing buffers. maxArrayLength = 64 KiB covers
        /// every SSH packet (hard cap 35000 bytes plus frame/pad/MAC slack);
        /// maxArraysPerBucket = 4096 lets thousands of in-flight connections
        /// hold rentals simultaneously without falling back to allocation.
        /// </summary>
        public static readonly ArrayPool<byte> Packets =
            ArrayPool<byte>.Create(maxArrayLength: 64 * 1024, maxArraysPerBucket: 4096);
    }
}
