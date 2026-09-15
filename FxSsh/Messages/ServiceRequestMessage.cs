using System.Text;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_SERVICE_REQUEST (5) message (RFC 4253 section 10).
    /// The client sends it to ask the server to start a named service, e.g.
    /// "ssh-userauth".
    /// </summary>
    [Message("SSH_MSG_SERVICE_REQUEST", MessageNumber)]
    public class ServiceRequestMessage : Message
    {
        internal const byte MessageNumber = 5;

        /// <summary>
        /// Gets the name of the requested service, e.g. "ssh-userauth".
        /// </summary>
        public string ServiceName { get; private set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_SERVICE_REQUEST (5).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the service name from the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            ServiceName = reader.ReadString(Encoding.ASCII);
        }
    }
}
