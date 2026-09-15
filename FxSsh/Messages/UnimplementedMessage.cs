namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_UNIMPLEMENTED (3) message (RFC 4253 section 11.4).
    /// Sent in reply to a message whose type number is unsupported, echoing
    /// the packet sequence number of the rejected message.
    /// </summary>
    [Message("SSH_MSG_UNIMPLEMENTED", MessageNumber)]
    public class UnimplementedMessage : Message
    {
        internal const byte MessageNumber = 3;

        /// <summary>
        /// Gets or sets the packet sequence number of the message that was
        /// not implemented.
        /// </summary>
        public uint SequenceNumber { get; set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_UNIMPLEMENTED (3).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the packet sequence number from the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            SequenceNumber = reader.ReadUInt32();
        }

        /// <summary>
        /// Writes the packet sequence number to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(SequenceNumber);
        }
    }
}
