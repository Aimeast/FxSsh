using System;
using System.Text;

namespace SshNet.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
    public class FailureMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 51;

        public override void Load(byte[] bytes)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write("publickey", Encoding.ASCII); // only accept public key
                worker.Write(false);

                return worker.ToArray();
            }
        }
    }
}
