using System;
using System.Threading;

namespace FxSsh.Services
{
    /// <summary>
    /// Ownership wrapper for one inbound CHANNEL_DATA payload as it travels
    /// from the transport into ConnectionService's asynchronous message loop.
    ///
    /// The session's decrypted receive buffer is recycled as soon as the
    /// message has been queued, so ConnectionService copies the payload once
    /// into a pooled buffer and attaches it to the message. The public
    /// <see cref="Channel.DataReceived"/> event exposes a transient view of
    /// that buffer; an internal consumer (the forwarding bridge or SFTP
    /// engine) can take ownership with <see cref="TryRetainOrCopy"/> and
    /// release it when the bytes have been consumed, avoiding a second copy.
    /// If nobody retains it, the message loop releases the rental after
    /// dispatch.
    /// </summary>
    internal sealed class ChannelDataLease : IDisposable
    {
        private const int Owned = 0;
        private const int Retained = 1;
        private const int Released = 2;

        private readonly ReadOnlyMemory<byte> _memory;
        private byte[] _buffer;
        private int _state;

        private ChannelDataLease(ReadOnlyMemory<byte> memory, byte[] buffer)
        {
            _memory = memory;
            _buffer = buffer;
            _state = Owned;
        }

        /// <summary>
        /// Gets a transient view over the payload. The memory is only valid
        /// until the lease is released; consumers that need it later must
        /// retain or copy it.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The lease was released.</exception>
        public ReadOnlyMemory<byte> Memory => Volatile.Read(ref _state) == Released
            ? throw new ObjectDisposedException(nameof(ChannelDataLease))
            : _memory;

        /// <summary>
        /// Wraps caller-owned memory that cannot be retained past the
        /// callback (e.g. a test or a host passing a byte[] to
        /// <see cref="Channel.OnData(ReadOnlyMemory{byte})"/>).
        /// </summary>
        internal static ChannelDataLease Wrap(ReadOnlyMemory<byte> data)
            => new(data, null);

        /// <summary>
        /// Copies <paramref name="data"/> into a pooled buffer owned by the
        /// returned lease.
        /// </summary>
        internal static ChannelDataLease CopyFrom(ReadOnlyMemory<byte> data)
        {
            if (data.IsEmpty)
                return new ChannelDataLease(ReadOnlyMemory<byte>.Empty, null);

            var buffer = SshBuffers.Packets.Rent(data.Length);
            data.Span.CopyTo(buffer);
            return new ChannelDataLease(buffer.AsMemory(0, data.Length), buffer);
        }

        /// <summary>
        /// Transfers ownership of the pooled buffer to the caller when this
        /// lease still owns it. A non-owning, already-retained, or released
        /// lease yields a fresh pooled copy instead, so the caller always
        /// receives a lease it owns and must dispose.
        /// </summary>
        /// <returns>True when ownership was transferred without a copy.</returns>
        internal bool TryRetainOrCopy(out ChannelDataLease owned)
        {
            if (Volatile.Read(ref _state) == Released)
                throw new ObjectDisposedException(nameof(ChannelDataLease));

            if (_buffer != null
                && Interlocked.CompareExchange(ref _state, Retained, Owned) == Owned)
            {
                owned = this;
                return true;
            }

            owned = CopyFrom(_memory);
            return false;
        }

        /// <summary>
        /// Releases the dispatcher's ownership. A lease already retained by
        /// a consumer is left for that consumer to dispose.
        /// </summary>
        internal void ReleaseIfNotRetained()
        {
            if (_buffer != null
                && Interlocked.CompareExchange(ref _state, Released, Owned) == Owned)
            {
                ReturnBuffer();
            }
        }

        /// <summary>Releases the owned pooled buffer (idempotent).</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _state, Released) == Released)
                return;
            ReturnBuffer();
        }

        private void ReturnBuffer()
        {
            var buffer = Interlocked.Exchange(ref _buffer, null);
            if (buffer != null)
                SshBuffers.Packets.Return(buffer);
        }
    }
}
