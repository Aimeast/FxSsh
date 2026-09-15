using System;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents an inbound message whose type number has no registered
    /// message type. It keeps the packet sequence number and the raw type
    /// byte so the caller can answer with an <see cref="UnimplementedMessage"/>.
    /// </summary>
    public class UnknownMessage : Message
    {
        /// <summary>
        /// Gets or sets the packet sequence number of the unrecognized message.
        /// </summary>
        public uint SequenceNumber { get; set; }

        /// <summary>
        /// Gets or sets the unrecognized SSH message number read from the payload.
        /// </summary>
        public byte UnknownMessageType { get; set; }

        /// <summary>
        /// Gets the SSH message number; an unknown message has no valid one.
        /// </summary>
        /// <exception cref="NotSupportedException">Always; an <see cref="UnknownMessage"/> is never serialised.</exception>
        public override byte MessageType { get { throw new NotSupportedException(); } }

        /// <summary>
        /// Creates the SSH_MSG_UNIMPLEMENTED reply that echoes this message's
        /// packet sequence number.
        /// </summary>
        /// <returns>An <see cref="UnimplementedMessage"/> referencing this packet.</returns>
        public UnimplementedMessage MakeUnimplementedMessage()
        {
            return new UnimplementedMessage()
            {
                SequenceNumber = SequenceNumber
            };
        }
    }
}
