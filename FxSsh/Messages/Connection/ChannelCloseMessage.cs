
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_CLOSE message (RFC 4254 section 5.3),
    /// used to shut down a channel. The sender must not send more data on
    /// the channel after sending this message.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_CLOSE", MessageNumber)]
    public class ChannelCloseMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 97;

        /// <summary>Gets or sets the recipient channel: the remote channel number this message is addressed to.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_CLOSE.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the recipient channel from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
        }

        /// <summary>Writes the recipient channel into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
        }
    }
}
