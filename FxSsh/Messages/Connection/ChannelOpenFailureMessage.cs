using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN_FAILURE message
    /// (RFC 4254 section 5.1), sent to reject a channel open request.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_OPEN_FAILURE", MessageNumber)]
    public class ChannelOpenFailureMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 92;

        /// <summary>Gets or sets the recipient channel: the sender channel number from the rejected SSH_MSG_CHANNEL_OPEN.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets or sets the <see cref="ChannelOpenFailureReason"/> explaining why the open request was refused.</summary>
        public ChannelOpenFailureReason ReasonCode { get; set; }

        /// <summary>Gets or sets a human-readable description of the failure.</summary>
        public string Description { get; set; }

        /// <summary>Gets or sets the RFC 3066 language tag of <see cref="Description"/>; written as "en" when not set.</summary>
        public string Language { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_OPEN_FAILURE.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the failure details from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            ReasonCode = (ChannelOpenFailureReason)reader.ReadUInt32();
            Description = reader.ReadString(Encoding.ASCII);
            Language = reader.ReadString(Encoding.ASCII);
        }

        /// <summary>Writes the failure details into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.Write((uint)ReasonCode);
            writer.Write(Description, Encoding.ASCII);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}
