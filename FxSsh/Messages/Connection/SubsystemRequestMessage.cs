using System.Text;
using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "subsystem" request
    /// (RFC 4254 section 6.5), which runs a named subsystem, such as
    /// "sftp", on the channel.
    /// </summary>
    public class SubsystemRequestMessage : ChannelRequestMessage
    {
        /// <summary>Gets the subsystem name to run, such as "sftp".</summary>
        public string Name { get; private set; }

        /// <summary>Reads the base request fields and the subsystem name from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the request-specific data.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            Name = reader.ReadString(Encoding.ASCII);
        }
    }
}
