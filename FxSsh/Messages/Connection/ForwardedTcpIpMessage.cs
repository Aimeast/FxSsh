using System;
using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN "forwarded-tcpip" request
    /// (RFC 4254 section 7.2), which opens a channel for a TCP/IP connection
    /// accepted by a listener on the remote side.
    /// </summary>
    public class ForwardedTcpIpMessage : ChannelOpenMessage
    {
        /// <summary>Gets the address the remote listener accepted the connection on.</summary>
        public string Address { get; private set; }

        /// <summary>Gets the port the remote listener accepted the connection on.</summary>
        public uint Port { get; private set; }

        /// <summary>Gets the IP address of the host that connected to the remote listener.</summary>
        public string OriginatorIPAddress { get; private set; }

        /// <summary>Gets the TCP port on the originating host.</summary>
        public uint OriginatorPort { get; private set; }

        /// <summary>Reads the base open fields and the connection details from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the channel-type-specific data.</param>
        /// <exception cref="ArgumentException">Thrown when the channel type is not "forwarded-tcpip".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (ChannelType != "forwarded-tcpip")
                throw new ArgumentException(string.Format("Channel type {0} is not valid.", ChannelType));

            Address = reader.ReadString(Encoding.ASCII);
            Port = reader.ReadUInt32();
            OriginatorIPAddress = reader.ReadString(Encoding.ASCII);
            OriginatorPort = reader.ReadUInt32();
        }
    }
}
