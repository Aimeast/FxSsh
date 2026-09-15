using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST message (RFC 4254 section 5.4),
    /// which requests an action on a channel, such as "pty-req", "shell",
    /// "exec", "env", or "subsystem". Typed subclasses such as
    /// <see cref="PtyRequestMessage"/> and <see cref="CommandRequestMessage"/>
    /// model the individual request payloads.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_REQUEST", MessageNumber)]
    public class ChannelRequestMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 98;

        /// <summary>Gets or sets the recipient channel: the remote channel number the request targets.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets or sets the request name, such as "pty-req", "shell", "exec", "env", "subsystem", "exit-status", or "exit-signal".</summary>
        public string RequestType { get; set; }

        /// <summary>Gets or sets a value indicating whether the recipient must reply with SSH_MSG_CHANNEL_SUCCESS or SSH_MSG_CHANNEL_FAILURE.</summary>
        public bool WantReply { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_REQUEST.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the recipient channel, request name, and reply flag from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            RequestType = reader.ReadString(Encoding.ASCII);
            WantReply = reader.ReadBoolean();
        }

        /// <summary>Writes the recipient channel, request name, and reply flag into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.Write(RequestType, Encoding.ASCII);
            writer.Write(WantReply);
        }
    }
}
