using System.Net;

namespace FxSsh
{
    /// <summary>
    /// Represents the settings an <see cref="SshServer"/> uses to bind its
    /// listener and to identify itself to clients during the version exchange.
    /// </summary>
    public class StartingInfo
    {
        /// <summary>
        /// The default TCP port the server listens on when no port is
        /// specified.
        /// </summary>
        public const int DefaultPort = 22;

        /// <summary>
        /// Initializes a new instance of the <see cref="StartingInfo"/> class
        /// that listens on all interfaces (<see cref="IPAddress.IPv6Any"/>)
        /// on <see cref="DefaultPort"/> and announces the banner
        /// "SSH-2.0-FxSsh".
        /// </summary>
        public StartingInfo()
            : this(IPAddress.IPv6Any, DefaultPort, "SSH-2.0-FxSsh")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="StartingInfo"/> class.
        /// </summary>
        /// <param name="localAddress">The local IP address the server binds to.</param>
        /// <param name="port">The TCP port the server listens on.</param>
        /// <param name="serverBanner">
        /// The protocol version string the server presents during the version
        /// exchange (RFC 4253 section 4.2), e.g. "SSH-2.0-FxSsh".
        /// </param>
        public StartingInfo(IPAddress localAddress, int port, string serverBanner)
        {
            LocalAddress = localAddress;
            Port = port;
            ServerBanner = serverBanner;
        }

        /// <summary>
        /// Gets the local IP address the server binds to.
        /// </summary>
        public IPAddress LocalAddress { get; private set; }

        /// <summary>
        /// Gets the TCP port the server listens on.
        /// </summary>
        public int Port { get; private set; }

        /// <summary>
        /// Gets the protocol version string the server presents to clients
        /// during the version exchange.
        /// </summary>
        public string ServerBanner { get; private set; }
    }
}
