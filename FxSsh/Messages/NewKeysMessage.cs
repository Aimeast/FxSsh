namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_NEWKEYS (21) message (RFC 4253 section 7.3).
    /// Sent at the end of key exchange to signal that all following packets
    /// use the new keys; it carries no payload fields.
    /// </summary>
    [Message("SSH_MSG_NEWKEYS", MessageNumber)]
    public class NewKeysMessage : Message
    {
        internal const byte MessageNumber = 21;

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_NEWKEYS (21).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the payload, which is empty per RFC 4253 section 7.3.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
        }

        /// <summary>
        /// Writes the payload, which is empty per RFC 4253 section 7.3.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
