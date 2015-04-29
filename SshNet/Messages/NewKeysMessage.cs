using System;

namespace SshNet.Messages
{
    [Message("SSH_MSG_NEWKEYS", MessageNumber)]
    public class NewKeysMessage : Message
    {
        private const byte MessageNumber = 21;

        public override void Load(byte[] bytes)
        {
            var number = bytes[0];
            if (number != MessageNumber)
                throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

        }

        public override byte[] GetPacket()
        {
            return new byte[] { MessageNumber };
        }
    }
}
