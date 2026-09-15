using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Server-side construction shell for an outbound
    /// SSH_MSG_CHANNEL_OPEN "forwarded-tcpip" (RFC 4254 section 7.2).
    ///
    /// This is NOT registered with [Message]: it is only ever sent by the
    /// server (never received), so it does not participate in the receive
    /// dispatch table. The receive side of forwarded-tcpip open arrives as
    /// a plain ChannelOpenMessage and is LoadFrom-ed into ForwardedTcpIpMessage.
    /// </summary>
    public class ForwardedTcpIpOpenMessage : ChannelOpenMessage
    {
        /// <summary>The host the server-side listener bound to.</summary>
        public string ConnectedAddress { get; set; }

        /// <summary>The port the server-side listener bound to.</summary>
        public uint ConnectedPort { get; set; }

        /// <summary>Remote peer address that connected to the listener.</summary>
        public string OriginatorIPAddress { get; set; }

        /// <summary>Remote peer port that connected to the listener.</summary>
        public uint OriginatorPort { get; set; }

        /// <summary>
        /// Construct an outbound forwarded-tcpip channel open.
        /// </summary>
        /// <param name="senderChannel">Server-side channel id to claim.</param>
        /// <param name="initialWindowSize">Server initial window size.</param>
        /// <param name="maximumPacketSize">Server max packet size.</param>
        /// <param name="connectedAddress">Host the listener bound to.</param>
        /// <param name="connectedPort">Port the listener bound to.</param>
        /// <param name="originatorIPAddress">Remote peer address.</param>
        /// <param name="originatorPort">Remote peer port.</param>
        public ForwardedTcpIpOpenMessage(
            uint senderChannel, uint initialWindowSize, uint maximumPacketSize,
            string connectedAddress, uint connectedPort,
            string originatorIPAddress, uint originatorPort)
        {
            SenderChannel = senderChannel;
            InitialWindowSize = initialWindowSize;
            MaximumPacketSize = maximumPacketSize;
            ConnectedAddress = connectedAddress;
            ConnectedPort = connectedPort;
            OriginatorIPAddress = originatorIPAddress;
            OriginatorPort = originatorPort;
        }

        /// <summary>Writes the forwarded-tcpip channel open into the outgoing packet.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write("forwarded-tcpip", Encoding.ASCII);
            writer.Write(SenderChannel);
            writer.Write(InitialWindowSize);
            writer.Write(MaximumPacketSize);
            writer.Write(ConnectedAddress ?? string.Empty, Encoding.ASCII);
            writer.Write(ConnectedPort);
            writer.Write(OriginatorIPAddress ?? string.Empty, Encoding.ASCII);
            writer.Write(OriginatorPort);
        }
    }
}
