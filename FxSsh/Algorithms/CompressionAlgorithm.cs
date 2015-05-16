
namespace SshNet.Algorithms
{
    public abstract class CompressionAlgorithm
    {
        public abstract byte[] Compress(byte[] input);

        public abstract byte[] Decompress(byte[] input);
    }
}
