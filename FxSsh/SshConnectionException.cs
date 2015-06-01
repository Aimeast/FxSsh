using System;

namespace FxSsh
{
    public class SshConnectionException : Exception
    {
        public SshConnectionException()
        {
        }

        public SshConnectionException(string message, DisconnectReason disconnectReason = DisconnectReason.None)
            : base(message)
        {
            DisconnectReason = disconnectReason;
        }

        public DisconnectReason DisconnectReason { get; private set; }
    }
}
