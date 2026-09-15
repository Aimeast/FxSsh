using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_REQUEST (50) message (RFC 4252
    /// section 5). Carries the user name, the requested service and the
    /// authentication method name; subclasses add the method-specific fields.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_REQUEST", MessageNumber)]
    public class RequestMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 50;

        /// <summary>
        /// Gets the user name the client is attempting to authenticate as.
        /// </summary>
        public string Username { get; protected set; }

        /// <summary>
        /// Gets the service the client wants to start after authentication,
        /// typically "ssh-connection".
        /// </summary>
        public string ServiceName { get; protected set; }

        /// <summary>
        /// Gets the authentication method name, e.g. "none", "password" or
        /// "publickey".
        /// </summary>
        public string MethodName { get; protected set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_REQUEST (50).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the user name, service name and method name from the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            Username = reader.ReadString(Encoding.UTF8);
            ServiceName = reader.ReadString(Encoding.ASCII);
            MethodName = reader.ReadString(Encoding.ASCII);
        }
    }
}
