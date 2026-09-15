using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Base class for the SSH protocol services multiplexed over a session
    /// ("ssh-userauth" and "ssh-connection"; service names per RFC 4250
    /// section 4.7, requested via SSH_MSG_SERVICE_REQUEST, RFC 4253 section
    /// 10). A service receives the messages addressed to its service name
    /// once the request for it has succeeded.
    /// </summary>
    public abstract class SshService
    {
        /// <summary>
        /// The session this service is registered with; used to send messages
        /// and to reach session-level state.
        /// </summary>
        protected internal readonly Session _session;

        /// <summary>
        /// Initializes a new instance of the <see cref="SshService"/> class.
        /// </summary>
        /// <param name="session">The session that instantiated this service.</param>
        public SshService(Session session)
        {
            ArgumentNullException.ThrowIfNull(session);

            _session = session;
        }

        /// <summary>
        /// Releases service resources when the session tears its services down
        /// (once the receive loop ends, e.g. on disconnect). Services holding
        /// sockets, listeners or loops must override this to shut them down.
        /// </summary>
        internal protected abstract void CloseService();
    }
}
