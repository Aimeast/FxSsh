using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Counter (CTR) mode transform per RFC 4344: the keystream is built by
    /// concatenating counter blocks (the IV, incremented as a big-endian integer
    /// for each successive block), ECB-encrypting the concatenated blocks with
    /// the underlying cipher, and XORing the result with the plaintext.
    /// </summary>
    public class CtrModeCryptoTransform : ICryptoTransform
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly ICryptoTransform _transform;
        private readonly byte[] _iv;
        private readonly byte[] _block;

        // Reused keystream buffer. CTR is a stream cipher: the whole packet's
        // consecutive counter blocks are built in one shot and encrypted with
        // a single TransformBlock call, instead of one AES invocation per
        // 16-byte block (a 32KB SSH packet previously triggered ~2048
        // cascading managed-to-native AES calls). 64KB covers every SSH
        // packet (hard cap 35000 bytes) plus slack; a fallback path keeps the
        // original per-block semantics for larger inputs.
        private readonly byte[] _ks;


        /// <summary>
        /// Initializes a new instance of the <see cref="CtrModeCryptoTransform"/> class,
        /// reconfiguring the algorithm to ECB mode with no padding so it encrypts the
        /// raw counter blocks.
        /// </summary>
        /// <param name="algorithm">The symmetric algorithm (e.g. AES) used to encrypt the counter blocks.</param>
        public CtrModeCryptoTransform(SymmetricAlgorithm algorithm)
        {
            ArgumentNullException.ThrowIfNull(algorithm);

            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _transform = algorithm.CreateEncryptor();
            _iv = algorithm.IV;
            _block = new byte[algorithm.BlockSize >> 3];
            _ks = new byte[1 << 16];
        }

        /// <summary>Gets a value indicating whether the transform can be reused (always true; the CTR state is carried entirely in the counter).</summary>
        public bool CanReuseTransform
        {
            get { return true; }
        }

        /// <summary>Gets a value indicating whether multiple blocks can be transformed in one call (always true).</summary>
        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>Gets the input block size in bits.</summary>
        public int InputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        /// <summary>Gets the output block size in bits.</summary>
        public int OutputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        /// <summary>
        /// XORs the specified region of the input buffer with the CTR keystream,
        /// advancing the counter so consecutive calls continue the same keystream.
        /// </summary>
        /// <param name="inputBuffer">The buffer containing the data to transform.</param>
        /// <param name="inputOffset">The offset into the input buffer at which to begin.</param>
        /// <param name="inputCount">The number of bytes to transform; the final block may be partial.</param>
        /// <param name="outputBuffer">The buffer to write the transformed data to.</param>
        /// <param name="outputOffset">The offset into the output buffer at which to begin writing.</param>
        /// <returns>The number of bytes processed, rounded up to whole cipher blocks.</returns>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesPerBlock = InputBlockSize >> 3;
            var blocks = (inputCount + bytesPerBlock - 1) / bytesPerBlock;
            var ksLen = blocks * bytesPerBlock;

            // Hot path: the whole packet fits the keystream buffer. Build all
            // consecutive counter blocks, encrypt them in one AES call, then
            // XOR in 8-byte (ulong) chunks. Mathematically identical to the
            // per-block loop - same keystream, same counter carry - so the
            // byte stream is unchanged.
            if (ksLen <= _ks.Length)
            {
                for (var b = 0; b < blocks; b++)
                {
                    Buffer.BlockCopy(_iv, 0, _ks, b * bytesPerBlock, bytesPerBlock);
                    var k = _iv.Length;
                    while (--k >= 0 && ++_iv[k] == 0) ;
                }

                // Single native AES-ECB invocation over all counter blocks.
                _transform.TransformBlock(_ks, 0, ksLen, _ks, 0);

                // XOR 8 bytes at a time, then the byte tail. Uses
                // ReadUnaligned/WriteUnaligned because the input/output spans
                // may not be 8-byte aligned (e.g. the ETM send path calls
                // Transform(..., offset 4, ...)); MemoryMarshal.Cast would
                // throw on a misaligned span. x64 unaligned ulong access is
                // as fast as aligned, so there is no throughput cost.
                ref var ksRef = ref MemoryMarshal.GetReference(_ks.AsSpan(0, ksLen));
                ref var srcRef = ref MemoryMarshal.GetReference(inputBuffer.AsSpan(inputOffset, inputCount));
                ref var dstRef = ref MemoryMarshal.GetReference(outputBuffer.AsSpan(outputOffset, inputCount));

                var i = 0;
                for (; i <= inputCount - sizeof(ulong); i += sizeof(ulong))
                {
                    var k = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref ksRef, i));
                    var s = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref srcRef, i));
                    Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, i), k ^ s);
                }
                for (; i < inputCount; i++)
                    Unsafe.Add(ref dstRef, i) = (byte)(Unsafe.Add(ref ksRef, i) ^ Unsafe.Add(ref srcRef, i));

                // Same return contract as the fallback: bytes processed, rounded
                // up to whole blocks.
                return ksLen;
            }

            // Fallback: input larger than the keystream buffer. Retain the
            // original per-block semantics and _iv advancement so the counter
            // state stays consistent across calls.
            var written = 0;
            for (var i = 0; i < inputCount; i += bytesPerBlock)
            {
                // CTR is a stream cipher: the final block may be shorter than
                // the cipher block size (e.g. ETM packets where packet_length
                // is not encrypted and the encrypted portion is not
                // block-aligned). Only consume the bytes actually present.
                var blockLen = Math.Min(bytesPerBlock, inputCount - i);

                written += _transform.TransformBlock(_iv, 0, bytesPerBlock, _block, 0);

                for (var j = 0; j < blockLen; j++)
                    outputBuffer[outputOffset + i + j] = (byte)(_block[j] ^ inputBuffer[inputOffset + i + j]);

                var k = _iv.Length;
                while (--k >= 0 && ++_iv[k] == 0) ;
            }

            return written;
        }

        /// <summary>
        /// Transforms the final block of data. CTR applies no padding, so the
        /// output is simply the input XORed with the keystream.
        /// </summary>
        /// <param name="inputBuffer">The buffer containing the data to transform.</param>
        /// <param name="inputOffset">The offset into the input buffer at which to begin.</param>
        /// <param name="inputCount">The number of bytes to transform.</param>
        /// <returns>The transformed input; its length equals <paramref name="inputCount"/>.</returns>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        /// <summary>Releases the resources used by the current transform, including the underlying ECB encryptor.</summary>
        public void Dispose()
        {
            _transform.Dispose();
        }
    }
}
