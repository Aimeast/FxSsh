using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_GLOBAL_REQUEST (80) per RFC 4254 section 4.
    /// Sent either by client or server. The receiver replies with
    /// SSH_MSG_REQUEST_SUCCESS (81) or SSH_MSG_REQUEST_FAILURE (82)
    /// when want-reply is true.
    /// </summary>
    [Message("SSH_MSG_GLOBAL_REQUEST", MessageNumber)]
    public class GlobalRequestMessage : ConnectionServiceMessage
    {
        internal const byte MessageNumber = 80;

        /// <summary>Gets or sets the request name, such as "tcpip-forward", "cancel-tcpip-forward", or "keepalive@openssh.com".</summary>
        public string RequestName { get; set; }

        /// <summary>Gets or sets a value indicating whether the recipient must reply with SSH_MSG_REQUEST_SUCCESS or SSH_MSG_REQUEST_FAILURE.</summary>
        public bool WantReply { get; set; }

        /// <summary>
        /// Raw request-specific data that follows want-reply (may be empty).
        /// Keepalive has no data; tcpip-forward / cancel-tcpip-forward carry
        /// their own payload, which we do not parse here.
        /// </summary>
        public byte[] RequestData { get; set; } = System.Array.Empty<byte>();

        /// <summary>Gets the message number that identifies this message as SSH_MSG_GLOBAL_REQUEST.</summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Reads the request name and reply flag from the incoming packet;
        /// any remaining bytes are kept unparsed in <see cref="RequestData"/>.
        /// </summary>
        /// <param name="reader">The reader positioned at the start of the message payload.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            RequestName = reader.ReadString(Encoding.ASCII);
            WantReply = reader.ReadBoolean();
            // Remainder (request-specific data) is left unparsed; keepalive
            // carries none, and we do not support forward requests yet.
            RequestData = reader.GetRemainderBytes();
        }

        /// <summary>Writes the request name, reply flag, and any request-specific data into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(RequestName ?? string.Empty, Encoding.ASCII);
            writer.Write(WantReply);
            if (RequestData != null && RequestData.Length > 0)
                writer.WriteBytes(RequestData);
        }
    }
}
