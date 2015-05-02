using System;

namespace SshNet.Messages
{
    [Message("SSH_MSG_UNIMPLEMENTED", MessageNumber)]
    public class UnimplementedMessage : Message
    {
        private const byte MessageNumber = 3;

        public uint SequenceNumber { get; set; }

        public byte MessageType { get; set; }

        public override void Load(byte[] bytes)
        {
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write(SequenceNumber);

                return worker.ToArray();
            }
        }
    }
}
