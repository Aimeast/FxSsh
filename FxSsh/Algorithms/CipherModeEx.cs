
namespace FxSsh.Algorithms
{
    /// <summary>
    /// Specifies the block cipher mode an SSH encryption algorithm operates in.
    /// </summary>
    public enum CipherModeEx
    {
        /// <summary>
        /// Cipher Block Chaining mode, the SSH equivalent of
        /// <see cref="System.Security.Cryptography.CipherMode.CBC"/>.
        /// </summary>
        CBC,

        /// <summary>
        /// Counter mode, as specified for SSH by RFC 4344.
        /// </summary>
        CTR,

        /// <summary>
        /// AES-GCM AEAD mode for aes128-gcm@openssh.com / aes256-gcm@openssh.com
        /// (RFC 5647). Unlike CBC/CTR this is Authenticated Encryption - the
        /// GCM tag replaces the separate HMAC field, so the Session send/receive
        /// paths branch on IsAead instead of computing an HMAC.
        /// </summary>
        GCM,
    }
}
