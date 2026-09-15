
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_IGNORE message (RFC 4253 section 11.2),
    /// whose contents the receiver must silently discard.
    /// </summary>
    [Message("SSH_MSG_IGNORE", MessageNumber)]
    public class ShouldIgnoreMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 2;

        /// <summary>Gets the message number that identifies this message as SSH_MSG_IGNORE.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the message payload from the incoming packet; the ignore data is not parsed.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
        }
    }
}
