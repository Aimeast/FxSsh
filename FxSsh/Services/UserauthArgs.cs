using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class UserAuthArgs
    {
        public UserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);

            AuthMethod = "publickey";
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
            Username = username;
        }

        public UserAuthArgs(Session session, string username, string password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            AuthMethod = "password";
            Username = username;
            Password = password;
            Session = session;
        }

        public string AuthMethod { get; private set; }
        public Session Session { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string KeyAlgorithm { get; private set; }
        public string Fingerprint { get; private set; }
        public byte[] Key { get; private set; }
        public bool Result { get; set; }
    }
}
