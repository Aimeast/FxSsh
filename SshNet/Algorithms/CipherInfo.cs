using System;
using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public class CipherInfo
    {
        public CipherInfo(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode)
        {
            algorithm.KeySize = keySize;
            KeySize = algorithm.KeySize;
            BlockSize = algorithm.BlockSize;
            Cipher = (key, vi, isEncryption) => new EncryptionAlgorithm(algorithm, keySize, mode, key, vi, isEncryption);
        }

        public int KeySize { get; private set; }

        public int BlockSize { get; private set; }

        public Func<byte[], byte[], bool, EncryptionAlgorithm> Cipher { get; private set; }
    }
}
