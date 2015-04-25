using System.IO;
using System.IO.Compression;

namespace SshNet.Algorithms
{
    public class ZlibCompression : CompressionAlgorithm
    {
        public override byte[] Compress(byte[] input)
        {
            using (var ms = new MemoryStream())
            {
                using (var deflate = new DeflateStream(ms, CompressionMode.Compress))
                {
                    deflate.Write(input, 0, input.Length);
                }
                return ms.ToArray();
            }
        }

        public override byte[] Decompress(byte[] input)
        {
            using (var outs = new MemoryStream(4096))
            {
                using (var ins = new MemoryStream(input))
                {
                    using (var deflate = new DeflateStream(ins, CompressionMode.Decompress))
                    {
                        deflate.CopyTo(outs);
                    }
                }
                return outs.ToArray();
            }
        }
    }
}
