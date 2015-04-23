using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public abstract class KexAlgorithm
    {
        protected HashAlgorithm _hashAlgorithm;

        public abstract byte[] CreateKeyExchange();

        public abstract byte[] DecryptKeyExchange(byte[] exchangeData);

        public byte[] ComputeHash(byte[] input)
        {
            return _hashAlgorithm.ComputeHash(input);
        }
    }
}
