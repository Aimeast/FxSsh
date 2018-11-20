
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh.Messages.Connection;

namespace FxSsh.Services
{
    public class SessionChannel : Channel
    {
        public SessionChannel(ConnectionService connectionService,
            uint clientChannelId, uint clientInitialWindowSize, uint clientMaxPacketSize,
            uint serverChannelId)
            : base(connectionService, clientChannelId, clientInitialWindowSize, clientMaxPacketSize, serverChannelId)
        {

        }
    }
}
