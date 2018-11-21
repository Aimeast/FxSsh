using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class UserauthArgs
    {
        public UserauthArgs(Session s, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(fingerprint != null);
            Contract.Requires(key != null);

            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = s;
            Username = username;
        }

        public UserauthArgs(Session s, string username, string password)
        {
            Contract.Requires(username != null);
            Contract.Requires(password != null);

            Username = username;
            Password = password;
            Session = s;
        }
        public Session Session { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string KeyAlgorithm { get; private set; }
        public string Fingerprint { get; private set; }
        public byte[] Key { get; private set; }
        public bool Result { get; set; }
    }
}
