using System;

namespace SshNet.Messages
{
    [Message("SSH_MSG_KEXDH_REPLY", MessageNumber)]
    public class KeyExchangeDhReplyMessage : Message
    {
        private const byte MessageNumber = 31;

        public byte[] HostKey { get; set; }
        public byte[] F { get; set; }
        public byte[] Signature { get; set; }


        public override void Load(byte[] bytes)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.WriteBinary(HostKey);
                worker.WriteMpint(F);
                worker.WriteBinary(Signature);

                return worker.ToArray();
            }
        }
    }
}
