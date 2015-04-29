using System;
using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public class CipherInfo
    {
        public CipherInfo(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode)
        {
            KeySize = keySize;
            Cipher = (key, vi) => new EncryptionAlgorithm(algorithm, keySize, mode, key, vi);
        }

        public int KeySize { get; private set; }

        public Func<byte[], byte[], EncryptionAlgorithm> Cipher { get; private set; }
    }
}
