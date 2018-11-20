using System;
using System.Text;

namespace FxSsh.Messages.Connection
{
    public class DirectTcpIpMessage : ChannelOpenMessage
    {
        public string HostToConnect { get; set; }
        public UInt32 PortToConnect { get; set; }
        public string OriginatorIPAddress { get; set; }
        public UInt32 OriginatorPort { get; set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);
            /*
              byte      SSH_MSG_CHANNEL_OPEN
              string    "direct-tcpip"
              uint32    sender channel
              uint32    initial window size
              uint32    maximum packet size
              string    host to connect
              uint32    port to connect
              string    originator IP address
              uint32    originator port
              */
            this.HostToConnect = reader.ReadString(Encoding.UTF8);
            this.PortToConnect = reader.ReadUInt32();
            this.OriginatorIPAddress = reader.ReadString(Encoding.UTF8);
            this.OriginatorPort = reader.ReadUInt32();
        }
    }
}
