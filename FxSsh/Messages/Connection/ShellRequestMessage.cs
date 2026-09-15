using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "shell" request
    /// (RFC 4254 section 6.5), which asks the remote side to start an
    /// interactive shell on the channel. The request carries no
    /// request-specific data.
    /// </summary>
    public class ShellRequestMessage : ChannelRequestMessage
    {
    }
}
