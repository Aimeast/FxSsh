
namespace FxSsh.Services
{
    /// <summary>
    /// Represents a "session" channel (SSH_MSG_CHANNEL_OPEN type "session",
    /// RFC 4254 section 6): the channel type on which shells, command
    /// executions, subsystems, environment variables and PTY requests run.
    /// </summary>
    public class SessionChannel : Channel
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SessionChannel"/> class
        /// for a client-initiated session open.
        /// </summary>
        /// <param name="connectionService">The connection service that owns this channel.</param>
        /// <param name="clientChannelId">The channel identifier assigned by the client.</param>
        /// <param name="clientInitialWindowSize">The peer's initial receive window in bytes.</param>
        /// <param name="clientMaxPacketSize">The maximum packet size the peer accepts, in bytes.</param>
        /// <param name="serverChannelId">The channel identifier assigned by this server.</param>
        public SessionChannel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId)
            : base(connectionService, clientChannelId, clientInitialWindowSize, clientMaxPacketSize, serverChannelId)
        {

        }
    }
}
