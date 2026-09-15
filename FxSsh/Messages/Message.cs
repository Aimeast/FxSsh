using System;

namespace FxSsh.Messages
{
    /// <summary>
    /// Base class of all SSH protocol messages. A message wraps the binary
    /// payload that follows the packet length/padding framing: the first byte
    /// is the message number (RFC 4250 section 4.1) and the remaining bytes are
    /// the message-specific fields, encoded per RFC 4251. Subclasses decode
    /// those fields in <see cref="OnLoad"/> and encode them in <see cref="OnGetPacket"/>.
    /// </summary>
    public abstract class Message
    {
        /// <summary>
        /// Gets the SSH message number that identifies this message on the
        /// wire (RFC 4250 section 4.1). <see cref="Load"/> rejects a payload
        /// whose leading byte differs from this value.
        /// </summary>
        public abstract byte MessageType { get; }

        /// <summary>
        /// Gets or sets the raw payload bytes this message was loaded from.
        /// This is a zero-copy slice over the SSH receive buffer, which is
        /// recycled by the next inbound packet; callers that defer re-parsing
        /// must snapshot it first (see <see cref="SnapshotRawBytes"/>).
        /// </summary>
        protected ReadOnlyMemory<byte> RawBytes { get; set; }

        /// <summary>
        /// Materialise an independent copy of the wire bytes. RawBytes is a
        /// zero-copy slice over the SSH receive buffer, which is recycled by
        /// the next ReceiveMessage; anything that defers re-parsing RawBytes
        /// (e.g. ConnectionService's async message queue) MUST snapshot first
        /// or it will parse garbage from a later packet.
        /// </summary>
        internal void SnapshotRawBytes()
        {
            if (!RawBytes.IsEmpty)
                RawBytes = RawBytes.ToArray();
        }

        /// <summary>
        /// Parses <paramref name="bytes"/> as this message's payload. The
        /// leading message number must equal <see cref="MessageType"/>; the
        /// remaining fields are decoded by <see cref="OnLoad"/>.
        /// </summary>
        /// <param name="bytes">The raw payload bytes, starting with the message number.</param>
        /// <exception cref="ArgumentException">The payload's leading message number differs from <see cref="MessageType"/>, or a field value decoded by <see cref="OnLoad"/> is invalid.</exception>
        public void Load(ReadOnlyMemory<byte> bytes)
        {
            RawBytes = bytes;

            var reader = new SshDataReader(bytes);
            var number = reader.ReadByte();
            if (number != MessageType)
                throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

            OnLoad(reader);
        }

        /// <summary>
        /// Serialises this message — the message number followed by the fields
        /// encoded by <see cref="OnGetPacket"/> — into a new payload byte
        /// array. The caller frames it with packet length, padding and MAC to
        /// form the final binary packet.
        /// </summary>
        /// <returns>The raw payload bytes of this message.</returns>
        public byte[] GetPacket()
        {
            var writer = new SshDataWriter();
            writer.Write(MessageType);

            OnGetPacket(writer);

            return writer.ToByteArray();
        }

        /// <summary>
        /// Write this message's payload (MessageType + fields) directly into
        /// <paramref name="writer"/>. This is the zero-intermediate-array
        /// counterpart of <see cref="GetPacket"/>: the caller already owns
        /// the writer (typically backed by a pooled buffer) and is going to
        /// frame it with packet_length/padding_length itself, so we avoid
        /// the round-trip through an intermediate <c>byte[]</c> payload.
        ///
        /// The writer is not disposed here - the caller disposes it once it
        /// has finished framing.
        /// </summary>
        public void WritePayload(SshDataWriter writer)
        {
            ArgumentNullException.ThrowIfNull(writer);
            writer.Write(MessageType);
            OnGetPacket(writer);
        }

        /// <summary>
        /// Re-parses an already received message as a more specific message
        /// type; used, for example, to materialise a
        /// <see cref="KeyExchangeXInitMessage"/> subclass once the negotiated
        /// key exchange method is known.
        /// </summary>
        /// <typeparam name="T">The concrete message type to create, which must expose a parameterless constructor.</typeparam>
        /// <param name="message">The received message whose raw bytes are re-parsed.</param>
        /// <returns>A new instance of <typeparamref name="T"/> loaded from the raw bytes of <paramref name="message"/>.</returns>
        /// <exception cref="ArgumentException">The raw bytes are not a valid <typeparamref name="T"/> payload.</exception>
        public static T LoadFrom<T>(Message message) where T : Message, new()
        {
            ArgumentNullException.ThrowIfNull(message);

            var msg = new T();
            msg.Load(message.RawBytes);
            return msg;
        }

        /// <summary>
        /// Decodes the message-specific fields (the payload bytes after the
        /// message number) from <paramref name="reader"/>. The default
        /// implementation throws <see cref="NotSupportedException"/>.
        /// </summary>
        /// <param name="reader">A reader positioned at the first field after the message number.</param>
        protected virtual void OnLoad(SshDataReader reader)
        {
            ArgumentNullException.ThrowIfNull(reader);

            throw new NotSupportedException();
        }

        /// <summary>
        /// Encodes the message-specific fields (the payload bytes after the
        /// message number) into <paramref name="writer"/>. The default
        /// implementation throws <see cref="NotSupportedException"/>.
        /// </summary>
        /// <param name="writer">The writer the fields are encoded into.</param>
        protected virtual void OnGetPacket(SshDataWriter writer)
        {
            ArgumentNullException.ThrowIfNull(writer);

            throw new NotSupportedException();
        }
    }
}
