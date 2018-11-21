using System;
using System.Net;
using System.Text;

namespace FxSsh.Messages.Connection
{
    public class ForwardedTcpIpMessage : ChannelOpenMessage
    {
        public string Address { get; private set; }
        public uint Port { get; private set; }
        public string OriginatorIPAddress { get; private set; }
        public uint OriginatorPort { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
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
