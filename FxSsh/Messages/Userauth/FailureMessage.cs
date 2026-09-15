using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_FAILURE (51) message (RFC 4252
    /// section 5.1). Sent to reject an authentication attempt; this
    /// implementation always offers the "password,publickey" methods and
    /// never signals partial success.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
    public class FailureMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 51;

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_FAILURE (51).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes the fixed name-list of acceptable methods
        /// ("password,publickey") and partial-success = false to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write("password,publickey", Encoding.ASCII);
            writer.Write(false);
        }
    }
}
