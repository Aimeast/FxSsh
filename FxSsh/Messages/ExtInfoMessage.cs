using System.Collections.Generic;
using System.Text;

namespace FxSsh.Messages
{
    [Message("SSH_MSG_EXT_INFO", MessageNumber)]
    public class ExtInfoMessage : Message
    {
        private const byte MessageNumber = 7;
        internal const string ServerSignatureAlgorithms = "server-sig-algs";
        internal const string ExtendedInfoClient = "ext-info-c";

        public override byte MessageType { get { return MessageNumber; } }

        public Dictionary<string, string> Extensions { get; private set; } = new();

        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write((uint)Extensions.Count);
            foreach (var kvp in Extensions)
            {
                writer.Write(kvp.Key, Encoding.ASCII);
                writer.Write(kvp.Value, Encoding.ASCII);
            }
        }

        protected override void OnLoad(SshDataReader reader)
        {
            var count = reader.ReadUInt32();
            Extensions = new Dictionary<string, string>((int)count);
            for (uint i = 0; i < count; i++)
            {
                var key = reader.ReadString(Encoding.ASCII);
                var value = reader.ReadString(Encoding.ASCII);
                Extensions.Add(key, value);
            }
        }
    }
}
