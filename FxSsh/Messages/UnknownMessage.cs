using System;

namespace FxSsh.Messages
{
    public class UnknownMessage : Message
    {
        public uint SequenceNumber { get; set; }

        public byte UnknownMessageType { get; set; }

        public override byte MessageType { get { throw new NotSupportedException();} }

        public UnimplementedMessage MakeUnimplementedMessage()
        {
            return new UnimplementedMessage()
            {
                SequenceNumber = SequenceNumber
            };
        }
    }
}
