using System;
using System.Text;

namespace SshNet.Messages
{
    [Message("SSH_MSG_SERVICE_REQUEST", MessageNumber)]
    public class ServiceRequestMessage : Message
    {
        private const byte MessageNumber = 5;

        public string ServiceName { get; private set; }

        public override void Load(byte[] bytes)
        {
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                ServiceName = worker.ReadString(Encoding.ASCII);
            }
        }

        public override byte[] GetPacket()
        {
            throw new NotSupportedException();
        }
    }
}
