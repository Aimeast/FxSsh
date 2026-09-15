namespace FxSsh.Messages
{
    /// <summary>
    /// Base class of the exchange-init messages: SSH_MSG_KEXDH_INIT and
    /// SSH_MSG_KEX_ECDH_INIT share message number 30, so the concrete
    /// subclass is chosen from the negotiated key exchange method (see
    /// <see cref="KeyExchangeDhInitMessage"/> and
    /// <see cref="KeyExchangeECDhInitMessage"/>). The base class itself leaves
    /// the payload unparsed.
    /// </summary>
    [Message("SSH_MSG_KEXDH_INIT,SSH_MSG_KEX_ECDH_INIT", MessageNumber)]
    public class KeyExchangeXInitMessage : Message
    {
        internal const byte MessageNumber = 30;

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_KEXDH_INIT and
        /// SSH_MSG_KEX_ECDH_INIT (30).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Leaves the payload unparsed; the concrete subclass decodes the
        /// exchange-specific key material.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
        }
    }
}
