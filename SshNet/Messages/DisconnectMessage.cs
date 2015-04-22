using System;
using System.Diagnostics.Contracts;

namespace SshNet.Messages
{
    [Message("SSH_MSG_DISCONNECT", 1)]
    public class DisconnectMessage : Message
    {
        public DisconnectMessage(DisconnectReason reasonCode, string description = "", string language = "en")
        {
            Contract.Requires(description != null);
            Contract.Requires(language != null);

            ReasonCode = reasonCode;
            Description = description;
            Language = language;
        }

        public DisconnectReason ReasonCode { get; private set; }
        public string Description { get; private set; }
        public string Language { get; private set; }

        public override void Load(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public override byte[] GetPacket()
        {
            throw new NotImplementedException();
        }
    }
}
