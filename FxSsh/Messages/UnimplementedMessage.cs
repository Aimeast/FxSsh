using System;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_UNIMPLEMENTED", MessageNumber)]
    public class UnimplementedMessage : Message
    {
        private const byte MessageNumber = 3;

        public uint SequenceNumber { get; set; }

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnLoad(SshDataWorker reader)
        {
            SequenceNumber = reader.ReadUInt32();
        }

        protected override void OnGetPacket(SshDataWorker writer)
        {
            writer.Write(SequenceNumber);
        }
    }
}
