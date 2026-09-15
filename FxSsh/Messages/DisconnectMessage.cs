using System;
using System.Text;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_DISCONNECT (1) message (RFC 4253 section 11.1).
    /// Either side sends it to terminate the connection, giving a reason code,
    /// a human-readable description and the description's language tag.
    /// </summary>
    [Message("SSH_MSG_DISCONNECT", MessageNumber)]
    public class DisconnectMessage : Message
    {
        internal const byte MessageNumber = 1;

        /// <summary>
        /// Initializes a new instance of the <see cref="DisconnectMessage"/>
        /// class without field values, e.g. for deserialising a received packet.
        /// </summary>
        public DisconnectMessage()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DisconnectMessage"/>
        /// class for sending a disconnection to the peer.
        /// </summary>
        /// <param name="reasonCode">The reason for the disconnection (RFC 4253 section 11.1).</param>
        /// <param name="description">A human-readable description of the reason, or an empty string.</param>
        /// <param name="language">The language tag of <paramref name="description"/>; defaults to "en".</param>
        public DisconnectMessage(DisconnectReason reasonCode, string description = "", string language = "en")
        {
            ArgumentNullException.ThrowIfNull(description);
            ArgumentNullException.ThrowIfNull(language);

            ReasonCode = reasonCode;
            Description = description;
            Language = language;
        }

        /// <summary>
        /// Gets the reason code for the disconnection (RFC 4253 section 11.1).
        /// </summary>
        public DisconnectReason ReasonCode { get; private set; }

        /// <summary>
        /// Gets the human-readable description of the disconnection reason.
        /// </summary>
        public string Description { get; private set; }

        /// <summary>
        /// Gets the language tag of <see cref="Description"/>.
        /// </summary>
        public string Language { get; private set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_DISCONNECT (1).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the reason code, description and optional language tag from
        /// the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            ReasonCode = (DisconnectReason)reader.ReadUInt32();
            Description = reader.ReadString(Encoding.UTF8);
            if (reader.DataAvailable >= 4)
                Language = reader.ReadString(Encoding.UTF8);
        }

        /// <summary>
        /// Writes the reason code, description and language tag to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write((uint)ReasonCode);
            writer.Write(Description, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.UTF8);
        }
    }
}
