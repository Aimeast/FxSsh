using System;

namespace SshNet.Messages.Userauth
{
    [Message("SSH_MSG_USERAUTH_SUCCESS", MessageNumber)]
    public class SuccessMessage : UserauthServiceMessage
    {
        private const byte MessageNumber = 52;

        public override void Load(byte[] bytes)
        {
            throw new NotSupportedException();
        }

        public override byte[] GetPacket()
        {
            return new byte[] { MessageNumber };
        }
    }
}
