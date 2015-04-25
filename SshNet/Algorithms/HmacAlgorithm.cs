using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public class HmacAlgorithm
    {
        private readonly KeyedHashAlgorithm _algorithm;

        public HmacAlgorithm(KeyedHashAlgorithm algorithm)
        {
            Contract.Requires(algorithm != null);

            _algorithm = algorithm;
        }

        public int DigestLength
        {
            get { return _algorithm.HashSize >> 3; }
        }

        public byte[] ComputeHash(byte[] input)
        {
            return _algorithm.ComputeHash(input);
        }
    }
}
