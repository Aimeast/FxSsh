using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class PasswordUserauthArgs : UserauthArgs
    {
        public PasswordUserauthArgs(string username, string pwd)
        {
            Contract.Requires(username != null);
            Contract.Requires(pwd != null);

            this.Username = username;
            this.Password = pwd;
        }

        public string Username { get; private set; }
        public string Password { get; private set; }
    }
}
