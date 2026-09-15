namespace FxSsh.Messages
{
    /// <summary>
    /// Base class of the exchange-reply messages: SSH_MSG_KEXDH_REPLY and
    /// SSH_MSG_KEX_ECDH_REPLY share message number 31, and subclasses (see
    /// <see cref="KeyExchangeDhReplyMessage"/> and
    /// <see cref="KeyExchangeECDhReplyMessage"/>) add the server's host key,
    /// public value and signature.
    /// </summary>
    [Message("SSH_MSG_KEXDH_REPLY,SSH_MSG_KEX_ECDH_REPLY", MessageNumber)]
    public class KeyExchangeXReplyMessage : Message
    {
        internal const byte MessageNumber = 31;

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_KEXDH_REPLY and
        /// SSH_MSG_KEX_ECDH_REPLY (31).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes no payload fields; subclasses add the exchange-specific data.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
