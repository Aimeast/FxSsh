using System;
using System.Buffers;

namespace FxSsh
{
    /// <summary>
    /// An <see cref="IMemoryOwner{T}"/> over a rental from the dedicated
    /// SSH packet pool (<see cref="SshBuffers.Packets"/>), used to transfer
    /// ownership of a copied forwarding chunk through a Channel into an async
    /// send pump without allocating a fresh byte[] per packet. Dispose returns
    /// the rental to the pool.
    ///
    /// The caller must copy the source bytes into the owned memory before
    /// enqueuing (the inbound SSH slice is recycled once the DataReceived
    /// callback returns, so the copy itself is unavoidable); this type only
    /// removes the per-packet heap allocation from that copy. Rent and Return
    /// always pair on the same dedicated pool, so the caller never touches
    /// the pool directly.
    /// </summary>
    public sealed class PooledMemoryOwner : IMemoryOwner<byte>
    {
        private byte[] _buffer;
        private readonly int _length;

        /// <summary>Rent a pooled buffer of at least <paramref name="length"/> bytes.</summary>
        public PooledMemoryOwner(int length)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);

            _buffer = SshBuffers.Packets.Rent(length);
            _length = length;
        }

        /// <summary>
        /// Gets the memory over the rented buffer, spanning the length
        /// requested at construction.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The owner has been disposed.</exception>
        public Memory<byte> Memory => _buffer == null
            ? throw new ObjectDisposedException(nameof(PooledMemoryOwner))
            : _buffer.AsMemory(0, _length);

        /// <summary>
        /// Returns the rented buffer to the packet pool. Calling this method
        /// more than once is safe; only the first call returns the buffer.
        /// </summary>
        public void Dispose()
        {
            var buffer = System.Threading.Interlocked.Exchange(ref _buffer, null);
            if (buffer != null)
                SshBuffers.Packets.Return(buffer);
        }
    }
}
