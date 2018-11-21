using System.Net;

namespace FxSsh
{
    public class StartingInfo
    {
        public const int DefaultPort = 22;

        public StartingInfo()
            : this(IPAddress.IPv6Any, DefaultPort, "SSH-2.0-FxSsh")
        {
        }

        public StartingInfo(IPAddress localAddress, int port, string serverBanner)
        {
            LocalAddress = localAddress;
            Port = port;
            ServerBanner = serverBanner;
        }

        public IPAddress LocalAddress { get; private set; }
        public int Port { get; private set; }

        public string ServerBanner { get; private set; }
    }
}
