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
        /// the password. The boolean preceding it is read and ignored; it is
        /// the obsolete "old password" flag, which RFC 4252 requires to be
        /// FALSE.
        /// </summary>
        /// <exception cref="ArgumentException">The request uses a method name other than "password".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "password")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));

            var isFalse = reader.ReadBoolean();
            Password = reader.ReadString(Encoding.ASCII);
        }
    }
}
