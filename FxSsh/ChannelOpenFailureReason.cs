using System.ComponentModel;

namespace FxSsh
{
    /// <summary>
    /// Specifies the reason codes carried by SSH_MSG_CHANNEL_OPEN_FAILURE
    /// (RFC 4254 section 5.1) when the server refuses to open a channel.
    /// </summary>
    public enum ChannelOpenFailureReason
    {
        /// <summary>Placeholder for reason code 0, which the protocol never sends.</summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        None = 0, // Not used by protocol
        /// <summary>The server prohibits opening channels of the requested type (SSH_OPEN_ADMINISTRATIVELY_PROHIBITED).</summary>
        AdministrativelyProhibited = 1,
        /// <summary>The connection attempt to the requested destination failed (SSH_OPEN_CONNECT_FAILED).</summary>
        ConnectFailed = 2,
        /// <summary>The channel type is unknown to the server (SSH_OPEN_UNKNOWN_CHANNEL_TYPE).</summary>
        UnknownChannelType = 3,
        /// <summary>The server lacks the resources to open the channel (SSH_OPEN_RESOURCE_SHORTAGE).</summary>
        ResourceShortage = 4,
    }
}
