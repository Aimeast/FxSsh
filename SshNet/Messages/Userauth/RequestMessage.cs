using System;
using System.Text;

namespace SshNet.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_REQUEST", MessageNumber)]
    public class RequestMessage : UserauthServiceMessage
    {
        protected const byte MessageNumber = 50;

        public string Username { get; protected set; }
        public string ServiceName { get; protected set; }
        public string MethodName { get; protected set; }

        public byte[] RawBytes { get; private set; }

        public override void Load(byte[] bytes)
        {
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                Username = worker.ReadString(Encoding.UTF8);
                ServiceName = worker.ReadString(Encoding.ASCII);
                MethodName = worker.ReadString(Encoding.ASCII);
            }
            RawBytes = bytes;
        }

        public override byte[] GetPacket()
        {
            throw new NotSupportedException();
        }
    }
}
