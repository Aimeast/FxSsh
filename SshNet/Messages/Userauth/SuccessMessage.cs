using System;

namespace SshNet.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_SUCCESS", MessageNumber)]
    public class SuccessMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 52;

        protected override byte MessageType { get { return MessageNumber; } }

        protected override void OnGetPacket(SshDataWorker writer)
        {
        }
    }
}
