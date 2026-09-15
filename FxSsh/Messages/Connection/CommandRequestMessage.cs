using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "exec" request
    /// (RFC 4254 section 6.5), which asks the remote side to run a single
    /// command on the channel.
    /// </summary>
    public class CommandRequestMessage : ChannelRequestMessage
    {
        /// <summary>Gets the command line to execute on the remote side.</summary>
        public string Command { get; private set; }

        /// <summary>Reads the base request fields and the command from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the request-specific data.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            Command = reader.ReadString(Encoding.ASCII);
        }
    }
}
