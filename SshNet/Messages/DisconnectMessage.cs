using System;
using System.Diagnostics.Contracts;
using System.Text;

namespace SshNet.Messages
{
    [Message("SSH_MSG_DISCONNECT", MessageNumber)]
    public class DisconnectMessage : Message
    {
        private const byte MessageNumber = 1;

        public DisconnectMessage()
        {
        }

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
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                ReasonCode = (DisconnectReason)worker.ReadUInt32();
                Description = worker.ReadString(Encoding.UTF8);
                Language = worker.ReadString(Encoding.UTF8);
            }
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write((uint)ReasonCode);
                worker.Write(Description, Encoding.UTF8);
                worker.Write(Language ?? "en", Encoding.UTF8);

                return worker.ToArray();
            }
        }
    }
}
