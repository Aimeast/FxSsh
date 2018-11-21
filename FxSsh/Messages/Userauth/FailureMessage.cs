using System;
using System.Text;

namespace FxSsh.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
    public class FailureMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 51;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnGetPacket(SshDataWorker writer)
        {
            writer.Write("password,publickey", Encoding.ASCII);
            writer.Write(false);
        }
    }
}
