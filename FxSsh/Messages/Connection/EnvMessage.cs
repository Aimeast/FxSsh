using System.Text;
using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "env" request
    /// (RFC 4254 section 6.4), which sets an environment variable for
    /// programs run on the channel.
    /// </summary>
    public class EnvMessage : ChannelRequestMessage
    {
        /// <summary>Gets the environment variable name.</summary>
        public string Name { get; private set; }

        /// <summary>Gets the value to assign to the variable.</summary>
        public string Value { get; private set; }

        /// <summary>Reads the base request fields and the variable name and value from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the request-specific data.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            Name = reader.ReadString(Encoding.ASCII);
            Value = reader.ReadString(Encoding.ASCII);
        }
    }
}
