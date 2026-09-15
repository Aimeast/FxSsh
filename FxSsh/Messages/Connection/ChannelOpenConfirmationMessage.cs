using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
    /// (RFC 4254 section 5.1), sent to accept a channel open request.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_OPEN_CONFIRMATION", MessageNumber)]
    public class ChannelOpenConfirmationMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 91;

        /// <summary>Gets or sets the recipient channel: the sender channel number from the SSH_MSG_CHANNEL_OPEN being confirmed.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets or sets the sender channel: the channel number assigned by this message's sender for subsequent messages on the channel.</summary>
        public uint SenderChannel { get; set; }

        /// <summary>Gets or sets the initial size in bytes of the sender's flow-control window for the channel.</summary>
        public uint InitialWindowSize { get; set; }

        /// <summary>Gets or sets the maximum size in bytes of a data payload the sender will accept on the channel.</summary>
        public uint MaximumPacketSize { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_OPEN_CONFIRMATION.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the channel numbers and flow-control parameters from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            SenderChannel = reader.ReadUInt32();
            InitialWindowSize = reader.ReadUInt32();
            MaximumPacketSize = reader.ReadUInt32();
        }

        /// <summary>Writes the channel numbers and flow-control parameters into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(SenderChannel);
            writer.Write(InitialWindowSize);
            writer.Write(MaximumPacketSize);
        }
    }
}
