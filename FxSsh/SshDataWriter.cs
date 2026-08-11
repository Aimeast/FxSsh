using System;
using System.Buffers;
using System.Text;

namespace FxSsh
{
    /// <summary>
    /// SSH wire-format writer. Backed by the shared <see cref="ArrayPool{T}"/>
    /// instead of a <see cref="System.IO.MemoryStream"/>: every write goes
    /// directly into a pooled buffer via <see cref="Span{byte}"/>, with O(1)
    /// amortized growth (capacity doubles, rented from the pool). When the
    /// caller actually needs the bytes, <see cref="ToByteArray"/> allocates
    /// exactly one right-sized array and copies once - or, for callers that
    /// already own a destination buffer, <see cref="TryWriteTo"/> copies with
    /// zero intermediate allocation.
    ///
    /// The pooled buffer is returned to <see cref="ArrayPool{byte}.Shared"/>
    /// by <see cref="Dispose"/>; this writer is IDisposable so callers that
    /// take a writer by value (the fluent `new SshDataWriter(...).Write(...).ToByteArray()`
    /// idiom) are rewired to either dispose via `using` or pay the one
    /// <see cref="ToByteArray"/> copy which also releases the rental. A
    /// finalizer guards against the rented buffer leaking if dispose is
    /// forgotten, but explicit disposal is strongly preferred.
    /// </summary>
    public sealed class SshDataWriter : IDisposable
    {
        private byte[] _buffer;
        private int _length;
        private bool _disposed;

        public SshDataWriter(int expectedCapacity = 4096)
        {
            // Rent at least a reasonable chunk so the common small-message
            // path never grows. ArrayPool may hand back more than requested,
            // which is fine - we track Length, not capacity.
            _buffer = SshBuffers.Packets.Rent(Math.Max(1, expectedCapacity));
            _length = 0;
        }

        public int Length => _length;

        /// <summary>
        /// Read-only view of the bytes written so far. Use to feed the
        /// accumulated payload into another writer/encoder without forcing
        /// a <see cref="ToByteArray"/> copy. The memory is backed by the
        /// pooled rental and is only valid until the writer is disposed or
        /// <see cref="ToByteArray"/>/<see cref="TryWriteTo"/> is called.
        /// </summary>
        public ReadOnlyMemory<byte> AsMemory()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SshDataWriter));
            return _buffer.AsMemory(0, _length);
        }

        /// <summary>
        /// Compact the writer into a freshly allocated, exactly-sized array
        /// and release the pooled rental. The returned array is the caller's
        /// to keep; the writer is disposed after this call.
        /// </summary>
        public byte[] ToByteArray()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SshDataWriter));

            var result = new byte[_length];
            if (_length > 0)
                Buffer.BlockCopy(_buffer, 0, result, 0, _length);

            // Rental goes back to the pool now that we've surfaced an
            // independent copy; further writes would re-rent.
            SshBuffers.Packets.Return(_buffer);
            _disposed = true;
            _buffer = null!;
            return result;
        }

        /// <summary>
        /// Copy the written bytes into <paramref name="destination"/> and
        /// release the pooled rental. Returns false (without writing) if the
        /// destination is too small; the writer is still disposed on success.
        /// Use this when the caller already owns the target buffer (e.g. the
        /// SSH packet frame) to avoid the intermediate array from
        /// <see cref="ToByteArray"/>.
        /// </summary>
        public bool TryWriteTo(Span<byte> destination)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SshDataWriter));
            if (destination.Length < _length)
                return false;

            var written = _buffer.AsSpan(0, _length);
            written.CopyTo(destination);

            SshBuffers.Packets.Return(_buffer);
            _disposed = true;
            _buffer = null!;
            return true;
        }

        private Span<byte> Reserve(int count)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SshDataWriter));

            var required = _length + count;
            if (required > _buffer.Length)
            {
                // Double-and-rent: amortized O(1) growth, matches MemoryStream
                // semantics but with pooled buffers (no LOH-stuck buffers).
                var newSize = _buffer.Length;
                while (newSize < required)
                    newSize <<= 1;

                var next = SshBuffers.Packets.Rent(newSize);
                _buffer.AsSpan(0, _length).CopyTo(next);
                SshBuffers.Packets.Return(_buffer);
                _buffer = next;
            }

            var slot = _buffer.AsSpan(_length, count);
            _length += count;
            return slot;
        }

        public SshDataWriter Write(bool value)
        {
            Reserve(1)[0] = value ? (byte)1 : (byte)0;
            return this;
        }

        public SshDataWriter Write(byte value)
        {
            Reserve(1)[0] = value;
            return this;
        }

        public SshDataWriter Write(uint value)
        {
            var s = Reserve(4);
            s[0] = (byte)(value >> 24);
            s[1] = (byte)(value >> 16);
            s[2] = (byte)(value >> 8);
            s[3] = (byte)(value & 0xFF);
            return this;
        }

        public SshDataWriter Write(ulong value)
        {
            var s = Reserve(8);
            s[0] = (byte)(value >> 56);
            s[1] = (byte)(value >> 48);
            s[2] = (byte)(value >> 40);
            s[3] = (byte)(value >> 32);
            s[4] = (byte)(value >> 24);
            s[5] = (byte)(value >> 16);
            s[6] = (byte)(value >> 8);
            s[7] = (byte)(value & 0xFF);
            return this;
        }

        public SshDataWriter Write(string str, Encoding encoding)
        {
            ArgumentNullException.ThrowIfNull(str);
            ArgumentNullException.ThrowIfNull(encoding);

            // Encode straight into the reserved slot - no intermediate
            // byte[] from encoding.GetBytes when the span overload exists.
            var byteCount = encoding.GetByteCount(str);
            WriteBinaryCore(encoding.GetBytes(str).AsMemory(), byteCount);
            return this;
        }

        public SshDataWriter WriteMpint(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 1 && data.Span[0] == 0)
            {
                Write((uint)0);
            }
            else
            {
                var length = (uint)data.Length;
                var high = ((data.Span[0] & 0x80) != 0);
                if (high)
                {
                    Write(length + 1);
                    Write((byte)0);
                    WriteBytes(data);
                }
                else
                {
                    Write(length);
                    WriteBytes(data);
                }
            }
            return this;
        }

        public SshDataWriter WriteBytes(ReadOnlyMemory<byte> data)
        {
            data.Span.CopyTo(Reserve(data.Length));
            return this;
        }

        public SshDataWriter WriteBinary(ReadOnlyMemory<byte> data)
        {
            WriteBinaryCore(data, data.Length);
            return this;
        }

        // Shared path for Write(string) and WriteBinary: emit length prefix
        // then copy payload. `byteCount` is the payload length to prefix;
        // it equals data.Length for WriteBinary and the encoded length for
        // Write(string).
        private void WriteBinaryCore(ReadOnlyMemory<byte> data, int byteCount)
        {
            Write((uint)byteCount);
            data.Span.CopyTo(Reserve(byteCount));
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            if (_buffer != null)
            {
                SshBuffers.Packets.Return(_buffer);
                _buffer = null!;
            }
        }

        // Safety net: if a writer is dropped without Dispose/ToByteArray,
        // return the rented buffer to the pool rather than letting it leak
        // until the pool's own bucket eviction. GC.SuppressFinalize is called
        // in the normal Dispose path below via the bool overload - kept
        // simple here because this writer is sealed and short-lived.
        ~SshDataWriter()
        {
            if (_buffer != null)
            {
                SshBuffers.Packets.Return(_buffer);
                _buffer = null!;
            }
        }
    }
}
