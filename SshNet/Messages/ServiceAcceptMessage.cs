using System;
using System.Text;

namespace SshNet.Messages
{
    [Message("SSH_MSG_SERVICE_ACCEPT", MessageNumber)]
    public class ServiceAcceptMessage : Message
    {
        private const byte MessageNumber = 6;

        public ServiceAcceptMessage(string name)
        {
            ServiceName = name;
        }

        public string ServiceName { get; private set; }

        public override void Load(byte[] bytes)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write(ServiceName, Encoding.ASCII);

                return worker.ToArray();
            }
        }
    }
}
