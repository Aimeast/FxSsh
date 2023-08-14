using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    public class DiffieHellmanGroupSha256 : KexAlgorithm
    {
        private readonly DiffieHellman _exchangeAlgorithm;

        public DiffieHellmanGroupSha256(DiffieHellman algorithm)
        {
            Contract.Requires(algorithm != null);

            _exchangeAlgorithm = algorithm;
            _hashAlgorithm = new SHA256CryptoServiceProvider();
        }

        public override byte[] CreateKeyExchange()
        {
            return _exchangeAlgorithm.CreateKeyExchange();
        }

        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            return _exchangeAlgorithm.DecryptKeyExchange(exchangeData);
        }
    }
}
