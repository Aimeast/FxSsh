using System.Text;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_SERVICE_ACCEPT (6) message (RFC 4253 section 10).
    /// The server sends it to confirm that it has started the service named in
    /// a preceding service request.
    /// </summary>
    [Message("SSH_MSG_SERVICE_ACCEPT", MessageNumber)]
    public class ServiceAcceptMessage : Message
    {
        internal const byte MessageNumber = 6;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServiceAcceptMessage"/> class.
        /// </summary>
        /// <param name="name">The name of the accepted service, e.g. "ssh-userauth".</param>
        public ServiceAcceptMessage(string name)
        {
            ServiceName = name;
        }

        /// <summary>
        /// Gets the name of the service that has been started.
        /// </summary>
        public string ServiceName { get; private set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_SERVICE_ACCEPT (6).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes the service name to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(ServiceName, Encoding.ASCII);
        }
    }
}
