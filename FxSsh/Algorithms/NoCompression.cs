using System;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the "none" compression algorithm (RFC 4253 section 6.2),
    /// which passes packet payloads through unchanged.
    /// </summary>
    public class NoCompression : CompressionAlgorithm
    {
        /// <summary>
        /// Gets <c>true</c>; the algorithm is the identity transform, so
        /// callers can skip the compression round trip entirely.
        /// </summary>
        public override bool IsIdentity => true;

        /// <summary>
        /// Returns the input unchanged.
        /// </summary>
        /// <param name="input">The data to compress.</param>
        /// <returns>The unmodified <paramref name="input"/> array.</returns>
        public override byte[] Compress(byte[] input)
        {
            return input;
        }

        /// <summary>
        /// Returns the input unchanged.
        /// </summary>
        /// <param name="input">The data to decompress.</param>
        /// <returns>The unmodified input.</returns>
        public override ReadOnlyMemory<byte> Decompress(ReadOnlyMemory<byte> input)
        {
            return input;
        }
    }
}
