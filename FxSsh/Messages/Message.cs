using System;

namespace FxSsh.Messages
{
    public abstract class Message
    {
        public abstract byte MessageType { get; }

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

        public void Load(ReadOnlyMemory<byte> bytes)
        {
            RawBytes = bytes;

            var reader = new SshDataReader(bytes);
            var number = reader.ReadByte();
            if (number != MessageType)
                throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

            OnLoad(reader);
        }

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

        public static T LoadFrom<T>(Message message) where T : Message, new()
        {
            ArgumentNullException.ThrowIfNull(message);

            var msg = new T();
            msg.Load(message.RawBytes);
            return msg;
        }

        protected virtual void OnLoad(SshDataReader reader)
        {
            ArgumentNullException.ThrowIfNull(reader);

            throw new NotSupportedException();
        }

        protected virtual void OnGetPacket(SshDataWriter writer)
        {
            ArgumentNullException.ThrowIfNull(writer);

            throw new NotSupportedException();
        }
    }
}
