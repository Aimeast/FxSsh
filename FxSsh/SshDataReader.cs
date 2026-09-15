using System;
using System.Text;

namespace FxSsh
{
    /// <summary>
    /// Reads SSH wire-format data types (RFC 4251 section 5) from an
    /// in-memory packet payload, advancing an internal cursor as values are
    /// consumed.
    /// </summary>
    public class SshDataReader
    {
        private readonly ReadOnlyMemory<byte> _bytes;
        private int _position;

        /// <summary>
        /// Initializes a new instance of the <see cref="SshDataReader"/> class
        /// positioned at the start of <paramref name="bytes"/>.
        /// </summary>
        /// <param name="bytes">The payload to read from.</param>
        public SshDataReader(ReadOnlyMemory<byte> bytes)
        {
            _bytes = bytes;
        }

        /// <summary>
        /// Gets the number of bytes not yet read.
        /// </summary>
        public long DataAvailable => _bytes.Length - _position;

        /// <summary>
        /// Reads an SSH <c>boolean</c> (RFC 4251 section 5): a single byte;
        /// any nonzero value is true.
        /// </summary>
        /// <returns>true if the byte read is nonzero; otherwise false.</returns>
        public bool ReadBoolean()
        {
            var num = ReadByte();

            return num != 0;
        }

        /// <summary>
        /// Reads an SSH <c>byte</c> (RFC 4251 section 5), advancing the
        /// position by 1 byte.
        /// </summary>
        /// <returns>The byte read.</returns>
        public byte ReadByte()
        {
            var span = ReadBytesAsMemory(1).Span;
            return span[0];
        }

        /// <summary>
        /// Reads an SSH <c>uint32</c> (RFC 4251 section 5) in big-endian
        /// order, advancing the position by 4 bytes.
        /// </summary>
        /// <returns>The value read.</returns>
        public uint ReadUInt32()
        {
            var span = ReadBytesAsMemory(4).Span;
            return (uint)(span[0] << 24 | span[1] << 16 | span[2] << 8 | span[3]);
        }

        /// <summary>
        /// Reads an SSH <c>uint64</c> (RFC 4251 section 5) in big-endian
        /// order, advancing the position by 8 bytes.
        /// </summary>
        /// <returns>The value read.</returns>
        public ulong ReadUInt64()
        {
            var span = ReadBytesAsMemory(8).Span;
            return ((ulong)span[0] << 56 | (ulong)span[1] << 48 | (ulong)span[2] << 40 | (ulong)span[3] << 32 |
                    (ulong)span[4] << 24 | (ulong)span[5] << 16 | (ulong)span[6] << 8 | span[7]);
        }

        /// <summary>
        /// Slices the next <paramref name="length"/> bytes out of the
        /// underlying buffer without copying and advances the position. The
        /// returned memory is a view over the source data, not an
        /// independent copy.
        /// </summary>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>A memory view over the bytes read.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Fewer than <paramref name="length"/> bytes remain in the buffer.
        /// </exception>
        public ReadOnlyMemory<byte> ReadBytesAsMemory(int length)
        {
            if (_position + length > _bytes.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            var bytes = _bytes.Slice(_position, length);
            _position += length;
            return bytes;
        }

        /// <summary>
        /// Reads an SSH <c>string</c> (RFC 4251 section 5): a <c>uint32</c>
        /// byte count followed by that many bytes, returned as a view over
        /// the source buffer without copying.
        /// </summary>
        /// <returns>A memory view over the payload bytes.</returns>
        public ReadOnlyMemory<byte> ReadBinaryAsMemory()
        {
            var length = ReadUInt32();
            return ReadBytesAsMemory((int)length);
        }

        /// <summary>
        /// Copies the next <paramref name="length"/> bytes into a new array
        /// and advances the position.
        /// </summary>
        /// <param name="length">The number of bytes to read.</param>
        /// <returns>A new array containing the bytes read.</returns>
        public byte[] ReadBytes(int length)
        {
            return ReadBytesAsMemory(length).ToArray();
        }

        /// <summary>
        /// Reads a length-prefixed binary blob (a <c>uint32</c> byte count
        /// followed by the payload) and copies it into a new array.
        /// </summary>
        /// <returns>A new array containing the payload bytes.</returns>
        public byte[] ReadBinary()
        {
            return ReadBinaryAsMemory().ToArray();
        }

        /// <summary>
        /// Reads an SSH <c>string</c> (a <c>uint32</c> byte count followed
        /// by the payload) and decodes it with <paramref name="encoding"/>.
        /// </summary>
        /// <param name="encoding">The encoding used to decode the payload bytes.</param>
        /// <returns>The decoded string.</returns>
        public string ReadString(Encoding encoding)
        {
            ArgumentNullException.ThrowIfNull(encoding);

            var span = ReadBinaryAsMemory().Span;
            return encoding.GetString(span);
        }

        /// <summary>
        /// Reads an SSH <c>mpint</c> (a <c>uint32</c> byte count followed by
        /// the big-endian two's-complement value) and copies it into a new
        /// array. A zero-length value is returned as a single-element array
        /// containing 0, and a redundant leading 0x00 byte (the
        /// positive-number padding written by
        /// <see cref="SshDataWriter.WriteMpint"/>) is stripped.
        /// </summary>
        /// <returns>The bytes of the value in big-endian order.</returns>
        public byte[] ReadMpint()
        {
            var span = ReadBinaryAsMemory().Span;

            if (span.Length == 0)
                return new byte[1];

            if (span[0] == 0)
            {
                return span.Slice(1).ToArray();
            }

            return span.ToArray();
        }

        /// <summary>
        /// Copies all bytes from the current position to the end of the
        /// buffer into a new array without advancing the position.
        /// </summary>
        /// <returns>A new array containing the remaining bytes.</returns>
        public byte[] GetRemainderBytes()
        {
            return _bytes[_position..].ToArray();
        }
    }
}
