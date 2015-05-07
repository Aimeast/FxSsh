using System;
using System.Text;

namespace SshNet.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_PK_OK", MessageNumber)]
    public class PublicKeyOkMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 60;

        public string KeyAlgorithmName { get; set; }
        public byte[] PublicKey { get; set; }

        public override void Load(byte[] bytes)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write(KeyAlgorithmName, Encoding.ASCII);
                worker.WriteBinary(PublicKey);

                return worker.ToArray();
            }
        }
    }
}
