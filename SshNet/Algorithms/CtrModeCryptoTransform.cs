using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public class CtrModeCryptoTransform : ICryptoTransform
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly ICryptoTransform _transform;
        private readonly byte[] _counter;


        public CtrModeCryptoTransform(SymmetricAlgorithm algorithm, bool encryptor)
        {
            algorithm.Mode = CipherMode.ECB;

            _algorithm = algorithm;
            _transform = encryptor
                ? algorithm.CreateEncryptor()
                : algorithm.CreateDecryptor();
            _counter = new byte[algorithm.IV.Length];
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        public int OutputBlockSize
        {
            get { return _algorithm.BlockSize; }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var bytesWritten = 0;
            var bytesPerBlock = InputBlockSize >> 3;

            for (var i = 0; i < inputCount; i += bytesPerBlock)
            {
                bytesWritten += _transform.TransformBlock(_counter, inputCount + i, bytesPerBlock, outputBuffer, outputOffset + 1);

                for (var j = 0; j < bytesPerBlock; j++)
                    outputBuffer[outputOffset + j] ^= inputBuffer[inputOffset + j];

                var k = _counter.Length;
                while (--k >= 0 && ++_counter[k] == 0) ;
            }

            return bytesWritten;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public void Dispose()
        {
            _transform.Dispose();
        }
    }
}
