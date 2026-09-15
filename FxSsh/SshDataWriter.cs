using System;
using System.Buffers;
using System.Text;

namespace FxSsh
{
    /// <summary>
    /// SSH wire-format writer. Backed by the library's dedicated SSH packet
    /// buffer pool instead of a <see cref="System.IO.MemoryStream"/>: every
    /// write goes directly into a pooled buffer via <c>Span&lt;byte&gt;</c>,
    /// with O(1) amortized growth (capacity doubles, rented from the pool).
    /// When the caller actually needs the bytes, <see cref="ToByteArray"/>
    /// allocates exactly one right-sized array and copies once - or, for
    /// callers that already own a destination buffer, <see cref="TryWriteTo"/>
    /// copies with zero intermediate allocation.
    ///
    /// The pooled buffer is returned to the pool by <see cref="Dispose"/>;
    /// this writer is IDisposable so callers that take a writer by value
    /// (the fluent `new SshDataWriter(...).Write(...).ToByteArray()` idiom)
    /// are rewired to either dispose via `using` or pay the one
    /// <see cref="ToByteArray"/> copy which also releases the rental. A
    /// finalizer guards against the rented buffer leaking if dispose is
    /// forgotten, but explicit disposal is strongly preferred.
    /// </summary>
    public sealed class SshDataWriter : IDisposable
    {
        private byte[] _buffer;
        private int _length;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="SshDataWriter"/> class
        /// backed by a buffer rented from the shared packet pool.
        /// </summary>
        /// <param name="expectedCapacity">
        /// The initial capacity to rent, in bytes; the pool may return a
        /// larger buffer. The buffer doubles in size when more space is
        /// needed.
        /// </param>
        public SshDataWriter(int expectedCapacity = 4096)
        {
            // Rent at least a reasonable chunk so the common small-message
            // path never grows. ArrayPool may hand back more than requested,
            // which is fine - we track Length, not capacity.
            _buffer = SshBuffers.Packets.Rent(Math.Max(1, expectedCapacity));
            _length = 0;
        }

        /// <summary>
        /// Gets the number of bytes written so far.
        /// </summary>
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

        /// <summary>
        /// Writes an SSH <c>boolean</c> (RFC 4251 section 5): a single byte
        /// with value 1 for true and 0 for false.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <returns>This writer, to allow call chaining.</returns>
        public SshDataWriter Write(bool value)
        {
            Reserve(1)[0] = value ? (byte)1 : (byte)0;
            return this;
        }

        /// <summary>
        /// Writes an SSH <c>byte</c> (RFC 4251 section 5): a single 8-bit
        /// value.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <returns>This writer, to allow call chaining.</returns>
        public SshDataWriter Write(byte value)
        {
            Reserve(1)[0] = value;
            return this;
        }

        /// <summary>
        /// Writes an SSH <c>uint32</c> (RFC 4251 section 5) in big-endian
        /// order, advancing the position by 4 bytes.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <returns>This writer, to allow call chaining.</returns>
        public SshDataWriter Write(uint value)
        {
            var s = Reserve(4);
            s[0] = (byte)(value >> 24);
            s[1] = (byte)(value >> 16);
            s[2] = (byte)(value >> 8);
            s[3] = (byte)(value & 0xFF);
            return this;
        }

        /// <summary>
        /// Writes an SSH <c>uint64</c> (RFC 4251 section 5) in big-endian
        /// order, advancing the position by 8 bytes.
        /// </summary>
        /// <param name="value">The value to write.</param>
        /// <returns>This writer, to allow call chaining.</returns>
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

        /// <summary>
        /// Writes an SSH <c>string</c> (RFC 4251 section 5): a <c>uint32</c>
        /// byte count followed by the bytes obtained by encoding
        /// <paramref name="str"/> with <paramref name="encoding"/>.
        /// </summary>
        /// <param name="str">The string to write.</param>
        /// <param name="encoding">The encoding used to produce the payload bytes.</param>
        /// <returns>This writer, to allow call chaining.</returns>
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

        /// <summary>
        /// Writes an SSH <c>mpint</c> (RFC 4251 section 5): a <c>uint32</c>
        /// byte count followed by <paramref name="data"/> interpreted as a
        /// big-endian two's-complement integer. A single zero byte is
        /// written as a zero-length value, and when the high bit of the
        /// first byte is set (which would otherwise read as a negative
        /// number) a 0x00 byte is inserted before the data to keep the
        /// value positive.
        /// </summary>
        /// <param name="data">The big-endian bytes of the integer value.</param>
        /// <returns>This writer, to allow call chaining.</returns>
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

        /// <summary>
        /// Writes raw bytes with no length prefix.
        /// </summary>
        /// <param name="data">The bytes to copy into the payload.</param>
        /// <returns>This writer, to allow call chaining.</returns>
        public SshDataWriter WriteBytes(ReadOnlyMemory<byte> data)
        {
            data.Span.CopyTo(Reserve(data.Length));
            return this;
        }

        /// <summary>
        /// Writes a length-prefixed binary blob: a <c>uint32</c> byte count
        /// followed by the bytes of <paramref name="data"/>.
        /// </summary>
        /// <param name="data">The payload bytes to write.</param>
        /// <returns>This writer, to allow call chaining.</returns>
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

        /// <summary>
        /// Returns the pooled buffer to the shared pool. Using the writer
        /// afterwards throws <see cref="ObjectDisposedException"/>; calling
        /// this more than once is a no-op.
        /// </summary>
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
        /// <summary>
        /// Finalizes an instance of the <see cref="SshDataWriter"/> class.
        /// Acts as a safety net for writers that are garbage-collected
        /// without having been disposed: the rented buffer is returned to
        /// the shared pool so it can be reused instead of leaking.
        /// </summary>
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
