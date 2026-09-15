using System;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the payload compression algorithm negotiated for an SSH
    /// connection (RFC 4253 section 6.2); the required "none" algorithm is
    /// provided by <see cref="NoCompression"/>.
    /// </summary>
    public abstract class CompressionAlgorithm
    {
        /// <summary>
        /// True when Compress/Decompress are identity transforms (the negotiated
        /// "none" algorithm). Callers can use this to skip the intermediate
        /// payload byte[] entirely on the wire hot path.
        /// </summary>
        public virtual bool IsIdentity => false;

        /// <summary>
        /// Compresses the supplied data.
        /// </summary>
        /// <param name="input">The data to compress.</param>
        /// <returns>The compressed data.</returns>
        public abstract byte[] Compress(byte[] input);

        /// <summary>
        /// Decompresses the supplied data.
        /// </summary>
        /// <param name="input">The data to decompress.</param>
        /// <returns>The decompressed data.</returns>
        public abstract ReadOnlyMemory<byte> Decompress(ReadOnlyMemory<byte> input);
    }
}
