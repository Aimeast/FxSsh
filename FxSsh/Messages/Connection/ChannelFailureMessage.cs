
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_FAILURE message (RFC 4254 section 5.4),
    /// the negative reply to a channel request that asked for a reply.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_FAILURE", MessageNumber)]
    public class ChannelFailureMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 100;

        /// <summary>Gets or sets the recipient channel: the remote channel number this message is addressed to.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_FAILURE.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Writes the recipient channel into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
        }
    }
}
