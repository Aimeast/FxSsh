using System;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_DATA message (RFC 4254 section 5.2),
    /// which carries application data flowing over a channel.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_DATA", MessageNumber)]
    public class ChannelDataMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 94;

        /// <summary>Gets or sets the recipient channel: the remote channel number this message is addressed to.</summary>
        public uint RecipientChannel { get; set; }

        /// <summary>Gets or sets the application data bytes carried by this message.</summary>
        public ReadOnlyMemory<byte> Data { get; set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_DATA.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the recipient channel and data payload from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RecipientChannel = reader.ReadUInt32();
            // Zero-copy: keep the slice over the decoded packet buffer rather
            // than ToArray()'ing into a fresh allocation. The packet buffer
            // is retained by Session.ReceiveMessage until LoadMessage returns,
            // which is synchronous here, so the slice stays valid for the
            // downstream OnData -> DataReceived -> consumer pump all of which
            // run on the same ConnectionService message loop thread before
            // the next ReceiveMessage reuses the buffer.
            Data = reader.ReadBinaryAsMemory();
        }

        /// <summary>Writes the recipient channel and data payload into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RecipientChannel);
            writer.WriteBinary(Data);
        }
    }
}
