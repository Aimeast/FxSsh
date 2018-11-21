using System.Diagnostics.Contracts;
using System.Net;

namespace FxSsh.Services
{
    public class TcpRequestArgs
    {
        public TcpRequestArgs(Session s, string host, uint port, string originatorIP, uint originatorPort)
        {
            Contract.Requires(s != null);
            Contract.Requires(host != null);
            Contract.Requires(originatorIP != null);

            Session = s;
            Host = host;
            Port = port;
            OriginatorIP = originatorIP;
            OriginatorPort = originatorPort;
        }

        public Session Session { get; private set; }
        public string Host { get; private set; }
        public uint Port { get; private set; }
        public string OriginatorIP { get; private set; }
        public uint OriginatorPort { get; private set; }
        public object Tag { get; set; }
    }
}
