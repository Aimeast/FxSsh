using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN message (RFC 4254 section 5.1),
    /// which requests a new channel. Concrete channel types (e.g. "session",
    /// "direct-tcpip") are modeled by subclasses such as
    /// <see cref="SessionOpenMessage"/> and <see cref="DirectTcpIpMessage"/>.
    /// </summary>
    [Message("SSH_MSG_CHANNEL_OPEN", MessageNumber)]
    public class ChannelOpenMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 90;

        /// <summary>Gets the channel type name, such as "session", "direct-tcpip", or "forwarded-tcpip".</summary>
        public string ChannelType { get; protected set; }

        /// <summary>Gets the sender channel: the channel number the sender of this message has assigned to the channel on its side.</summary>
        public uint SenderChannel { get; protected set; }

        /// <summary>Gets the initial size in bytes of the sender's flow-control window for the channel.</summary>
        public uint InitialWindowSize { get; protected set; }

        /// <summary>Gets the maximum size in bytes of a data payload the sender will accept on the channel.</summary>
        public uint MaximumPacketSize { get; protected set; }

        /// <summary>Gets the message number that identifies this message as SSH_MSG_CHANNEL_OPEN.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>Reads the channel type and open parameters from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            ChannelType = reader.ReadString(Encoding.ASCII);
            SenderChannel = reader.ReadUInt32();
            InitialWindowSize = reader.ReadUInt32();
            MaximumPacketSize = reader.ReadUInt32();
        }
    }
}
