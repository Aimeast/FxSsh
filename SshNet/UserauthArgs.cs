using System.Diagnostics.Contracts;

namespace SshNet
{
    public class UserauthArgs
    {
        public UserauthArgs(string keyAlgorithm, string keyHash, byte[] key)
        {
            Contract.Requires(keyAlgorithm != null);
            Contract.Requires(keyHash != null);
            Contract.Requires(key != null);

            KeyAlgorithm = keyAlgorithm;
            KeyHash = keyHash;
            Key = key;
        }

        public string KeyAlgorithm { get; private set; }
        public string KeyHash { get; private set; }
        public byte[] Key { get; private set; }
        public bool Result { get; set; }
    }
}
