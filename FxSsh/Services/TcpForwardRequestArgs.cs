using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Args for a reverse port forwarding request (SSH_MSG_GLOBAL_REQUEST
    /// "tcpip-forward"). The host decides whether to accept the listener
    /// by setting Accepted = true; default is false (reject).
    /// </summary>
    public sealed class TcpForwardRequestArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TcpForwardRequestArgs"/> class.
        /// </summary>
        /// <param name="address">The bind address the peer requested; empty means "any".</param>
        /// <param name="port">The bind port the peer requested; 0 means OS-assigned.</param>
        /// <param name="userAuthArgs">Authentication details of the user that requested the reverse forward.</param>
        public TcpForwardRequestArgs(string address, int port, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(address);

            Address = address;
            Port = port;
            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>Bind address the peer requested. Empty means "any".</summary>
        public string Address { get; private set; }

        /// <summary>Bind port the peer requested. 0 means "OS-assigned".</summary>
        public int Port { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user that requested the
        /// reverse forward.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }

        /// <summary>Host sets this to true to permit the listener; default false.</summary>
        public bool Accepted { get; set; }
    }
}
