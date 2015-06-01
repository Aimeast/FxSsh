using System;
using System.Diagnostics.Contracts;

namespace FxSsh.Algorithms
{
    [ContractClassFor(typeof(CompressionAlgorithm))]
    abstract class CompressionAlgorithmContract : CompressionAlgorithm
    {
        public override byte[] Compress(byte[] input)
        {
            Contract.Requires(input != null);

            throw new NotImplementedException();
        }

        public override byte[] Decompress(byte[] input)
        {
            Contract.Requires(input != null);

            throw new NotImplementedException();
        }
    }
}
