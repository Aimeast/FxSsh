using System;

namespace SshNet.Messages
{
    [Message("SSH_MSG_KEXDH_INIT", MessageNumber)]
    public class KeyExchangeDhInitMessage : Message
    {
        private const byte MessageNumber = 30;

        public byte[] E { get; private set; }

        public override void Load(byte[] bytes)
        {
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                E = worker.ReadMpint();
            }
        }

        public override byte[] GetPacket()
        {
            throw new NotSupportedException();
        }
    }
}
