using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FxSsh.Messages
{
    /// <summary>
    /// SSH_MSG_EXT_INFO (7) per RFC 8308 section 2.2.
    /// Sent immediately after SSH_MSG_NEWKEYS (under the new encryption keys)
    /// to advertise protocol extensions. The message carries a list of
    /// (name, value) pairs; the name is an ASCII string (extension identifier),
    /// and the value is a UTF-8 string whose semantics are defined per name.
    /// </summary>
    [Message("SSH_MSG_EXT_INFO", MessageNumber)]
    public class ExtInfoMessage : Message
    {
        internal const byte MessageNumber = 7;

        /// <summary>
        /// Extension name -> value dictionary.
        /// RFC 8308 requires that extensions be sent in ascending order by name.
        /// </summary>
        public Dictionary<string, string> Extensions { get; set; } = [];

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_EXT_INFO (7).
        /// </summary>
        public override byte MessageType => MessageNumber;

        /// <summary>
        /// Loads the extension count and the (name, value) pairs from the
        /// payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            var count = reader.ReadUInt32();
            var dict = new Dictionary<string, string>((int)count);
            for (int i = 0; i < count; i++)
            {
                var name = reader.ReadString(Encoding.ASCII);
                var value = reader.ReadString(Encoding.UTF8);
                dict[name] = value;
            }
            Extensions = dict;
        }

        /// <summary>
        /// Writes the extension count and the (name, value) pairs to the
        /// payload, in ascending order by name as required by RFC 8308
        /// section 2.2.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write((uint)Extensions.Count);

            // RFC 8308 section 2.2: extensions MUST be in ascending order by name.
            foreach (var kv in Extensions.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
            {
                writer.Write(kv.Key, Encoding.ASCII);
                writer.Write(kv.Value, Encoding.UTF8);
            }
        }
    }
}
