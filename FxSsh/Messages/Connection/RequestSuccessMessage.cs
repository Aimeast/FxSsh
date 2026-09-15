
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_REQUEST_SUCCESS (81) per RFC 4254 section 4.
    /// Reply to SSH_MSG_GLOBAL_REQUEST with want-reply true. No payload.
    /// </summary>
    [Message("SSH_MSG_REQUEST_SUCCESS", MessageNumber)]
    public class RequestSuccessMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 81;

        /// <summary>Gets the message number that identifies this message as SSH_MSG_REQUEST_SUCCESS.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the message payload from the incoming packet; this message carries no payload.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            // No payload per RFC 4254 section 4.
        }

        /// <summary>Writes the message payload into the outgoing packet; this message carries no payload.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
