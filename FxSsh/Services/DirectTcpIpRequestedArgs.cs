using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class DirectTcpIpRequestedArgs
    {
        public DirectTcpIpRequestedArgs(SessionChannel channel, string targetIP, uint targetPort, string origIP, uint origPort, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(targetIP != null);
            Contract.Requires(origIP != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            TargetIP = targetIP;
            OriginatorIP = origIP;
            TargetPort = targetPort;
            OriginatorPort = origPort;
            AttachedUserauthArgs = userauthArgs;
            Allow = false;
            DenialDescription = string.Empty;
            ReasonCode = ChannelOpenFailureReason.None;
        }

        public SessionChannel Channel { get; private set; }
        public string TargetIP { get; private set; }
        public string OriginatorIP { get; private set; }

        public uint TargetPort { get; private set; }

        public uint OriginatorPort { get; private set; }

        public bool Allow { get; set; }
        public string DenialDescription { get; set; }

        public ChannelOpenFailureReason ReasonCode { get; set; }

        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
