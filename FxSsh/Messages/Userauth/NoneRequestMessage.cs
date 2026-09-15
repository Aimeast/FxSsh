using System;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents an SSH_MSG_USERAUTH_REQUEST using the "none" method
    /// (RFC 4252 section 5). Most clients send it first to learn which
    /// authentication methods the server accepts.
    /// </summary>
    public class NoneRequestMessage : RequestMessage
    {
        /// <summary>
        /// Loads the base request fields and requires the method name to be
        /// "none".
        /// </summary>
        /// <exception cref="ArgumentException">The request uses a method name other than "none".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "none")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));
        }
    }
}
