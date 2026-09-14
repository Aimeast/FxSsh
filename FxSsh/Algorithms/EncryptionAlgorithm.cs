using System;
using System.ComponentModel;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class EncryptionAlgorithm
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly CipherModeEx _mode;
        private readonly ICryptoTransform _transform;

        // AEAD branch: replaces the streaming _transform with a single
        // per-packet invoker (IAeadTransform). Null when _mode is CBC/CTR.
        // The built-in implementation is GCM (GcmModeCryptoTransform); the
        // plugin ctor lets consumers supply their own (e.g. the test-side
        // chacha20-poly1305@openssh.com transform).
        private readonly IAeadTransform _aeadTransform;
        private readonly int _blockBytesSize;

        public EncryptionAlgorithm(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode, byte[] key, byte[] iv, bool isEncryption)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(iv);
            if (keySize != key.Length << 3)
                throw new ArgumentException("Key size must match the key length in bits.", nameof(keySize));

            _mode = mode;

            if (mode == CipherModeEx.GCM)
            {
                // RFC 5647 section 7.1 + OpenSSL SET_IV_FIXED(arg=-1): the full 12-byte
                // IV is materialised by key exchange - first 4 bytes fixed field,
                // last 8 bytes seed the invocation counter (NOT zero). AesGcm owns
                // the key; _algorithm is left null and the SymmetricAlgorithm
                // parameter is unused (CipherInfo's GCM ctor passes null), so we
                // do NOT ThrowIfNull(algorithm) here.
                if (iv.Length != 12)
                    throw new ArgumentException("AES-GCM IV must be 12 bytes (fixed(4) || invocation_counter(8), RFC 5647 section 7.1).", nameof(iv));

                _aeadTransform = new GcmModeCryptoTransform(key, iv);
                _blockBytesSize = 16;
                _algorithm = null;
                _transform = null;
                IsAead = true;
                return;
            }

            // CBC/CTR path: a SymmetricAlgorithm instance is mandatory.
            ArgumentNullException.ThrowIfNull(algorithm);

            algorithm.KeySize = keySize;
            algorithm.Key = key;
            algorithm.IV = iv;
            algorithm.Padding = PaddingMode.None;

            _algorithm = algorithm;
            _transform = CreateTransform(isEncryption);
            _aeadTransform = null;
            _blockBytesSize = algorithm.BlockSize >> 3;
            IsAead = false;
        }

        /// <summary>
        /// Plugin AEAD constructor for ciphers supplied from outside the library
        /// (e.g. chacha20-poly1305@openssh.com, whose transform lives in
        /// FxSsh.Tests). The transform owns the per-packet AEAD framing: it
        /// writes the packet_length field (plaintext AAD for GCM, encrypted for
        /// chacha20-poly1305@openssh.com), the ciphertext and the auth tag, and
        /// keys its nonce off the packet sequence number. The key material from
        /// key exchange is passed to the transform factory by CipherInfo.
        /// <paramref name="blockBytesSize"/> is the SSH binary packet protocol's
        /// padding alignment (16 for AES-GCM, 8 for chacha20-poly1305@openssh.com).
        /// </summary>
        public EncryptionAlgorithm(IAeadTransform aeadTransform, int blockBytesSize)
        {
            ArgumentNullException.ThrowIfNull(aeadTransform);
            if (blockBytesSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(blockBytesSize), blockBytesSize, "Block size must be positive.");

            _aeadTransform = aeadTransform;
            _blockBytesSize = blockBytesSize;
            _algorithm = null;
            _transform = null;
            IsAead = true;
        }

        /// <summary>
        /// True for AEAD ciphers (AES-GCM per RFC 5647, chacha20-poly1305@openssh.com).
        /// AEAD packets carry their auth tag inline and do NOT use a separate
        /// HMAC; Session.Send/ReceiveMessage branch on this to skip the HMAC
        /// computation and emit/parse the tag.
        /// </summary>
        public bool IsAead { get; }

        /// <summary>Block size in bytes used for padding alignment (16 for AES-GCM, 8 for chacha20-poly1305@openssh.com).</summary>
        public int BlockBytesSize => _blockBytesSize;

        /// <summary>AEAD auth tag length (16). Only valid when IsAead.</summary>
        public int TagBytes
        {
            get
            {
                if (_aeadTransform == null)
                    throw new InvalidOperationException("TagBytes is only defined for AEAD (GCM / chacha20-poly1305@openssh.com) algorithms.");
                return _aeadTransform.TagBytes;
            }
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for AEAD).</summary>
        public byte[] Transform(byte[] input)
        {
            var output = new byte[input.Length];
            Transform(input, input.Length, output);
            return output;
        }

        /// <summary>CTR/CBC streaming encrypt/decrypt (not valid for AEAD).</summary>
        public void Transform(byte[] input, byte[] output)
        {
            Transform(input, input.Length, output);
        }

        /// <summary>
        /// CTR/CBC streaming encrypt/decrypt over exactly
        /// <paramref name="inputLength"/> bytes (not valid for AEAD).
        ///
        /// <paramref name="inputLength"/> may be smaller than
        /// <paramref name="input"/>.Length - callers that hold a pooled buffer
        /// larger than the actual packet MUST pass the exact byte count:
        /// ICryptoTransform.TransformBlock processes the entire supplied
        /// count, and the CTR implementation advances its keystream counter
        /// by exactly that many bytes. Feeding it a rented buffer's full
        /// length would over-advance the counter and corrupt every subsequent
        /// packet's decryption.
        /// </summary>
        public void Transform(byte[] input, int inputLength, byte[] output)
        {
            Transform(input, 0, inputLength, output, 0);
        }

        /// <summary>
        /// CTR/CBC streaming encrypt/decrypt over exactly
        /// <paramref name="inputLength"/> bytes starting at
        /// <paramref name="inputOffset"/>, writing to <paramref name="outputOffset"/>
        /// (not valid for AEAD). Supports in-place use (input == output), which
        /// the ETM send path exploits to encrypt the packet body at [4..]
        /// without a scratch array.
        /// </summary>
        public void Transform(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            if (_transform == null)
                throw new InvalidOperationException("Transform is only valid for CBC/CTR; use EncryptAead/DecryptAead for AEAD.");
            if (inputLength < 0 || inputOffset < 0 || inputLength > input.Length - inputOffset)
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            if (outputOffset < 0 || inputLength > output.Length - outputOffset)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            _transform.TransformBlock(input, inputOffset, inputLength, output, outputOffset);
        }

        /// <summary>
        /// AEAD encrypt one SSH packet straight into <paramref name="destination"/>:
        /// <paramref name="frame"/> is [packet_length(4)][padding_length||payload||padding].
        /// Writes the on-wire length field (plaintext for GCM - it is the AAD
        /// per RFC 5647 section 7.3; encrypted for chacha20-poly1305@openssh.com),
        /// the ciphertext and the auth tag, ready to go on the wire as
        /// [length_field(4)][ciphertext][tag]. Caller must advance the outbound
        /// packet sequence separately (Session does so after the write).
        ///
        /// <paramref name="destination"/> must be at least
        /// <paramref name="frame"/>.Length + TagBytes long. No intermediate
        /// allocation on the hot path.
        /// </summary>
        public void EncryptAead(uint sequenceNumber, ReadOnlySpan<byte> frame, Span<byte> destination)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("EncryptAead is only valid for AEAD ciphers.");
            _aeadTransform.Encrypt(sequenceNumber, frame, destination);
        }

        /// <summary>
        /// AEAD: turn the 4 on-wire packet_length bytes into the plaintext
        /// length (identity for GCM; K2-keystream decrypt for
        /// chacha20-poly1305@openssh.com). Session calls this before reading
        /// the packet body so the length can be validated and bounded.
        /// </summary>
        public int DecryptPacketLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("DecryptPacketLength is only valid for AEAD ciphers.");
            return _aeadTransform.DecryptPacketLength(sequenceNumber, encryptedLength);
        }

        /// <summary>
        /// AEAD authenticate and decrypt one SSH packet straight into
        /// <paramref name="plaintextDestination"/>: <paramref name="lengthField"/>
        /// is the 4 on-wire length bytes (GCM AAD / chacha tag input) and
        /// <paramref name="ciphertextWithTag"/> is ciphertext || tag. The tag
        /// is verified before decryption; throws CryptographicException on
        /// mismatch - Session maps that to DisconnectReason.MacError, matching
        /// the HMAC path.
        ///
        /// <paramref name="plaintextDestination"/> must be at least
        /// <paramref name="ciphertextWithTag"/>.Length - TagBytes long.
        /// No intermediate allocation on the hot path.
        /// </summary>
        public void DecryptAead(uint sequenceNumber, ReadOnlySpan<byte> lengthField, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination)
        {
            if (_aeadTransform == null)
                throw new InvalidOperationException("DecryptAead is only valid for AEAD ciphers.");
            _aeadTransform.Decrypt(sequenceNumber, lengthField, ciphertextWithTag, plaintextDestination);
        }

        private ICryptoTransform CreateTransform(bool isEncryption)
        {
            switch (_mode)
            {
                case CipherModeEx.CBC:
                    _algorithm.Mode = CipherMode.CBC;
                    return isEncryption
                        ? _algorithm.CreateEncryptor()
                        : _algorithm.CreateDecryptor();
                case CipherModeEx.CTR:
                    return new CtrModeCryptoTransform(_algorithm);
                case CipherModeEx.GCM:
                    // GCM never reaches here: handled in the ctor's AEAD branch.
                    throw new InvalidOperationException("GCM has no streaming ICryptoTransform; use EncryptAead/DecryptAead.");
                default:
                    throw new InvalidEnumArgumentException(string.Format("Invalid mode: {0}", _mode));
            }
        }
    }
}
