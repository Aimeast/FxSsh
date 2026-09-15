
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_WINDOW_ADJUST message
    /// (RFC 4254 section 5.2), which grants additional flow-control window
    /// space to the sender of channel data after bytes have been consumed.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_WINDOW_ADJUST", MessageNumber)]
    public class ChannelWindowAdjustMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 93;

        /// <summary>Gets or sets the recipient channel: the remote channel whose flow-control window is being enlarged.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets or sets the number of bytes to add to the recipient's flow-control window.</summary>
        public uint BytesToAdd { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_WINDOW_ADJUST.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the recipient channel and window increment from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            BytesToAdd = reader.ReadUInt32();
        }

        /// <summary>Writes the recipient channel and window increment into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(BytesToAdd);
        }
    }
}
