using System;
using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN "direct-tcpip" request
    /// (RFC 4254 section 7.2), which asks the remote side to open a TCP/IP
    /// connection to a host reachable from it.
    /// </summary>
    public class DirectTcpIpMessage : ChannelOpenMessage
    {
        /// <summary>Gets the host name or IP address to connect to from the remote side.</summary>
        public string Host { get; private set; }

        /// <summary>Gets the TCP port to connect to.</summary>
        public uint Port { get; private set; }

        /// <summary>Gets the IP address of the host that originated the connection.</summary>
        public string OriginatorIPAddress { get; private set; }

        /// <summary>Gets the TCP port on the originating host.</summary>
        public uint OriginatorPort { get; private set; }

        /// <summary>Reads the base open fields and the TCP/IP target from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the channel-type-specific data.</param>
        /// <exception cref="ArgumentException">Thrown when the channel type is not "direct-tcpip".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (ChannelType != "direct-tcpip")
                throw new ArgumentException(string.Format("Channel type {0} is not valid.", ChannelType));

            Host = reader.ReadString(Encoding.ASCII);
            Port = reader.ReadUInt32();
            OriginatorIPAddress = reader.ReadString(Encoding.ASCII);
            OriginatorPort = reader.ReadUInt32();
        }
    }
}
