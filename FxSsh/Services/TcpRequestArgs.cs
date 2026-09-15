using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="ConnectionService.TcpForwardRequest"/>, raised
    /// when the peer opens a TCP/IP forwarding channel: "direct-tcpip" (the
    /// client wants to reach a host through the server) or "forwarded-tcpip"
    /// (a connection arrived on a port the client asked the server to listen
    /// on), per RFC 4254 section 7.
    /// </summary>
    public class TcpRequestArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TcpRequestArgs"/> class.
        /// </summary>
        /// <param name="channel">The channel opened for the forwarded connection.</param>
        /// <param name="host">The host to connect to ("direct-tcpip") or the address the connection arrived on ("forwarded-tcpip").</param>
        /// <param name="port">The port to connect to, or the port the connection arrived on.</param>
        /// <param name="originatorIP">The address of the machine on the client's side that originated the connection.</param>
        /// <param name="originatorPort">The port on the originator machine.</param>
        /// <param name="userAuthArgs">Authentication details of the user attached to the channel.</param>
        public TcpRequestArgs(SessionChannel channel, string host, int port, string originatorIP, int originatorPort, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(host);
            ArgumentNullException.ThrowIfNull(originatorIP);

            Channel = channel;
            Host = host;
            Port = port;
            OriginatorIP = originatorIP;
            OriginatorPort = originatorPort;
            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>
        /// Gets the channel opened for the forwarded connection.
        /// </summary>
        public SessionChannel Channel { get; private set; }

        /// <summary>
        /// Gets the host to connect to ("direct-tcpip") or the address the
        /// connection arrived on ("forwarded-tcpip").
        /// </summary>
        public string Host { get; private set; }

        /// <summary>
        /// Gets the port to connect to, or the port the connection arrived on.
        /// </summary>
        public int Port { get; private set; }

        /// <summary>
        /// Gets the address of the machine that originated the connection, as
        /// reported by the client.
        /// </summary>
        public string OriginatorIP { get; private set; }

        /// <summary>
        /// Gets the port on the machine that originated the connection.
        /// </summary>
        public int OriginatorPort { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user attached to the
        /// channel.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}
