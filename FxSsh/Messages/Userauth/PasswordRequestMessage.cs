using System;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents an SSH_MSG_USERAUTH_REQUEST using the "password" method
    /// (RFC 4252 section 8), carrying the user's plaintext password.
    /// </summary>
    public class PasswordRequestMessage : RequestMessage
    {
        /// <summary>
        /// Gets the plaintext password supplied by the client.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// Loads the base request fields, verifies the method name and reads
        /// the password. The boolean preceding it is the obsolete "old
        /// password" flag, which RFC 4252 section 8 requires to be FALSE;
        /// a TRUE value names a password-change request this server does not
        /// implement, so it is rejected rather than misread as a login.
        /// </summary>
        /// <exception cref="ArgumentException">The request uses a method name other than "password", or requests a password change.</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "password")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));

            var changePassword = reader.ReadBoolean();
            if (changePassword)
                throw new ArgumentException("Password-change requests are not supported.");

            // RFC 4252 section 8: password is a UTF-8 string, not ASCII.
            Password = reader.ReadString(Encoding.UTF8);
        }
    }
}
