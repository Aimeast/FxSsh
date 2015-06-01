using System;
using System.Diagnostics.Contracts;

namespace FxSsh.Algorithms
{
    [ContractClassFor(typeof(KexAlgorithm))]
    abstract class KexAlgorithmContract : KexAlgorithm
    {
        public override byte[] CreateKeyExchange()
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            Contract.Requires(exchangeData != null);

            throw new NotImplementedException();
        }
    }
}
