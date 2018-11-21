using System;
using System.Diagnostics.Contracts;
using System.Net;

namespace FxSsh.Services
{
    public class TcpRequestArgs
    {
        public TcpRequestArgs(Session s, string host, uint port, string originatorIP, uint originatorPort, Func<bool> Ready, Action<byte[]> OnData, Action OnDisconnect)
        {
            Contract.Requires(s != null);
            Contract.Requires(host != null);
            Contract.Requires(originatorIP != null);

            Session = s;
            Host = host;
            Port = port;
            OriginatorIP = originatorIP;
            OriginatorPort = originatorPort;
            ClientReady = Ready;
            OnServerData = OnData;
            OnServerDisconnect = OnDisconnect;
        }

        public Session Session { get; private set; }
        public string Host { get; private set; }
        public uint Port { get; private set; }
        public string OriginatorIP { get; private set; }
        public uint OriginatorPort { get; private set; }
        public object Tag { get; set; }
        public Func<bool> ClientReady { get; private set; }
        public Action<byte[]> OnServerData { get; private set; }
        public Action OnServerDisconnect { get; private set; }
        public Action<byte[]> OnClientData { get; set; }
        public Action OnClientDisconnect { get; set; }
    }
}
