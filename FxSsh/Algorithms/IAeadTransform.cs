using System;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Per-packet AEAD transform behind the SSH binary packet protocol's
    /// authenticated-encryption ciphers. Session.Send/ReceiveMessage consume
    /// it through EncryptionAlgorithm.EncryptAead / DecryptPacketLength /
    /// DecryptAead, which keeps the packet framing (length field handling,
    /// tag placement, per-packet nonce) inside the transform: the built-in
    /// AES-GCM implementation (GcmModeCryptoTransform, RFC 5647) transmits
    /// packet_length as plaintext AAD, while chacha20-poly1305@openssh.com
    /// encrypts it with a separate keystream and authenticates the encrypted
    /// bytes - both expose the same shape here.
    ///
    /// This is the AEAD extension point for AlgorithmSelection plug-ins:
    /// a consumer can register a cipher whose CipherInfo factory builds a custom
    /// IAeadTransform from the KEX-derived key without forking the library.
    /// </summary>
    public interface IAeadTransform
    {
        /// <summary>Auth tag length in bytes (16 for both AES-GCM and chacha20-poly1305@openssh.com).</summary>
        int TagBytes { get; }

        /// <summary>
        /// Turn the 4 on-wire packet_length bytes into the plaintext length:
        /// identity for AES-GCM (the field is plaintext), K2-keystream decrypt
        /// for chacha20-poly1305@openssh.com. Called before the packet body is
        /// read so the length can be validated and bounded.
        /// </summary>
        int DecryptPacketLength(uint sequenceNumber, ReadOnlySpan<byte> encryptedLength);

        /// <summary>
        /// Encrypt one SSH packet straight into <paramref name="destination"/>:
        /// <paramref name="frame"/> is [packet_length(4)][padding_length||payload||padding].
        /// Writes the on-wire length field (plaintext for GCM, encrypted for
        /// chacha20-poly1305@openssh.com), the ciphertext and the auth tag:
        /// [length_field(4)][ciphertext][tag]. <paramref name="destination"/>
        /// must be at least <paramref name="frame"/>.Length + TagBytes long.
        /// </summary>
        void Encrypt(uint sequenceNumber, ReadOnlySpan<byte> frame, Span<byte> destination);

        /// <summary>
        /// Authenticate and decrypt one SSH packet straight into
        /// <paramref name="plaintextDestination"/>: <paramref name="lengthField"/>
        /// is the 4 on-wire length bytes (GCM AAD / chacha tag input) and
        /// <paramref name="ciphertextWithTag"/> is ciphertext || tag. The tag
        /// is verified before decryption; throws CryptographicException on
        /// mismatch (Session maps that to DisconnectReason.MacError).
        /// </summary>
        void Decrypt(uint sequenceNumber, ReadOnlySpan<byte> lengthField, ReadOnlySpan<byte> ciphertextWithTag, Span<byte> plaintextDestination);
    }
}
