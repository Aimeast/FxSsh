using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// SSH packet MAC calculator. Backed by the static
    /// <see cref="HMACSHA256.HashData(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/> /
    /// <see cref="HMACSHA512.HashData(ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})"/>
    /// Span APIs (.NET 8) for the hot per-packet path: each MAC is one
    /// stateless invocation over a concatenated <c>seq || a || b</c> buffer,
    /// with zero allocations on the caller-owned-destination path (the seq
    /// prefix is stackalloc'd; the body lives in an ArrayPool buffer rented
    /// and returned around the call).
    ///
    /// The legacy <see cref="ComputeHash(byte[])"/> /
    /// <see cref="ComputeHash(byte[], byte[], uint)"/> entry points are kept
    /// for cold paths (key exchange) but rewritten to delegate to the same
    /// Span-based core, so there is exactly one MAC implementation.
    /// </summary>
    public class HmacAlgorithm
    {
        private readonly KeyedHashAlgorithm _algorithm;
        private readonly byte[] _key;
        private readonly int _digestLength;

        // Dispatch token: which static HashData to invoke. Avoids re-testing
        // the runtime type on every per-packet MAC.
        private readonly byte _kind; // 0 = HMACSHA256, 1 = HMACSHA512, 2 = fallback

        public HmacAlgorithm(KeyedHashAlgorithm algorithm, int keySize, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(algorithm);
            ArgumentNullException.ThrowIfNull(key);
            if (keySize != key.Length << 3)
                throw new ArgumentException("Key size must match the key length in bits.", nameof(keySize));

            // HashData is keyed by the raw key bytes, not by mutating the
            // algorithm instance's Key setter. Keep both the instance (for
            // DigestLength and algorithm-kind detection) and an independent
            // reference to the key bytes (cache once - KeyedHashAlgorithm.Key
            // returns a fresh array on every read).
            _algorithm = algorithm;
            algorithm.Key = key;
            _key = key;
            _digestLength = _algorithm.HashSize >> 3;
            _kind = algorithm is HMACSHA256 ? (byte)0
                : algorithm is HMACSHA512 ? (byte)1
                : (byte)2;
        }

        public int DigestLength => _digestLength;

        /// <summary>
        /// Compute MAC over <paramref name="input"/> only (b empty), returning a
        /// fresh array. Kept for the cold key-exchange MAC path; hot paths
        /// use the Span overload below.
        /// </summary>
        public byte[] ComputeHash(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);
            var dest = new byte[_digestLength];
            ComputeHashCore(ReadOnlySpan<byte>.Empty, input, 0u, dest);
            return dest;
        }

        /// <summary>
        /// Compute MAC over <c>seq || a || b</c> for SSH packet authentication
        /// (RFC 4253 section 6.4), returning a fresh array. The hot per-packet
        /// MAC calls should prefer the Span overload
        /// <see cref="ComputeHash(ReadOnlySpan{byte}, ReadOnlySpan{byte}, uint, Span{byte})"/>
        /// which writes straight into a caller-supplied destination and
        /// therefore performs zero allocations on the verified-good path.
        /// </summary>
        public byte[] ComputeHash(byte[] a, byte[] b, uint sequence)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            var dest = new byte[_digestLength];
            ComputeHashCore(a, b, sequence, dest);
            return dest;
        }

        /// <summary>
        /// Compute the SSH packet MAC <c>seq || a || b</c> straight into
        /// <paramref name="destination"/>. Zero allocations when the caller
        /// owns the destination (e.g. a stackalloc span or an
        /// ArrayPool-rented slice). Throws if <paramref name="destination"/>
        /// is shorter than <see cref="DigestLength"/>.
        ///
        /// The seq prefix is emitted by this method - callers pass only the
        /// two MAC body segments (typically the plaintext packet_length and
        /// the ciphertext), matching how Session.ReceiveMessage splits the
        /// ETM/non-ETM MAC inputs.
        /// </summary>
        public void ComputeHash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint sequence, Span<byte> destination)
        {
            if (destination.Length < _digestLength)
                throw new ArgumentException("Destination too short for MAC.", nameof(destination));
            ComputeHashCore(a, b, sequence, destination);
        }

        // Core MAC: concat seq || a || b into a pooled buffer and invoke the
        // stateless HMAC.HashData once. The concat is unavoidable because
        // HMACSHA256/512.HashData takes a single contiguous source - .NET
        // offers no streaming HMAC Span API. The pooled rental is returned
        // in finally, so the hot path's only heap traffic is one rent + one
        // return (ArrayPool bookkeeping, not GC pressure).
        private void ComputeHashCore(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, uint sequence, Span<byte> destination)
        {
            Span<byte> seq = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(seq, sequence);

            var dest = destination[.._digestLength];

            switch (_kind)
            {
                case 0: // HMACSHA256
                    HashConcat(seq, a, b, dest, (key, source, d) => HMACSHA256.HashData(key, source, d));
                    break;
                case 1: // HMACSHA512
                    HashConcat(seq, a, b, dest, (key, source, d) => HMACSHA512.HashData(key, source, d));
                    break;
                default:
                    // Fallback: streaming KeyedHashAlgorithm API (no Span
                    // overload exists for arbitrary KeyedHashAlgorithm). Used
                    // only by hypothetical non-SHA2 keyed hashes - none exist
                    // in the SSH algorithm registry today, but keeps the type
                    // honest. Retains the pre-Span allocations.
                    _algorithm.Initialize();
                    _algorithm.TransformBlock(seq.ToArray(), 0, 4, null, 0);
                    if (!a.IsEmpty)
                        _algorithm.TransformBlock(a.ToArray(), 0, a.Length, null, 0);
                    if (!b.IsEmpty)
                        _algorithm.TransformBlock(b.ToArray(), 0, b.Length, null, 0);
                    _algorithm.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                    _algorithm.Hash.AsSpan(0, _digestLength).CopyTo(dest);
                    break;
            }
        }

        // Concat seq || a || b into a pooled buffer and invoke the supplied
        // HashData. SSH MAC inputs are bounded by MaximumPacketLength
        // (~256KB), so a stack buffer is unsafe here - always rent from the
        // pool. The rental is returned before return; a and b were already in
        // the receive buffer (hot path), so the copies here are the
        // unavoidable concat into the pooled slot, not an extra allocation.
        private void HashConcat(
            ReadOnlySpan<byte> seq, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b,
            Span<byte> dest,
            HashDataDelegate hash)
        {
            var total = checked(4 + a.Length + b.Length);
            var rental = SshBuffers.Packets.Rent(total);
            try
            {
                var concat = rental.AsSpan(0, total);
                seq.CopyTo(concat);
                a.CopyTo(concat[4..]);
                b.CopyTo(concat[(4 + a.Length)..]);
                hash(_key, concat, dest);
            }
            finally
            {
                SshBuffers.Packets.Return(rental);
            }
        }

        // HMACSHA256/512.HashData both have the same shape:
        //   static int HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
        // We wrap with a delegate whose key param is `in` only because the
        // static API takes it by value - `in` lets us pass `_key` (a byte[])
        // implicitly converted to ReadOnlySpan<byte> at the call site without
        // an extra local.
        private delegate int HashDataDelegate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination);
    }
}
