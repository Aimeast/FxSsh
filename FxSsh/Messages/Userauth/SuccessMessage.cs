namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_SUCCESS (52) message (RFC 4252
    /// section 5.1). Sent to accept an authentication attempt; it carries no
    /// payload fields.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_SUCCESS", MessageNumber)]
    public class SuccessMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 52;

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_SUCCESS (52).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes the payload, which is empty.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
