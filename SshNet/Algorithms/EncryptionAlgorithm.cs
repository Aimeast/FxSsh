using System;
using System.ComponentModel;
using System.Diagnostics.Contracts;
using System.IO;
using System.Security.Cryptography;

namespace SshNet.Algorithms
{
    public class EncryptionAlgorithm
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly CipherModeEx _mode;

        public EncryptionAlgorithm(SymmetricAlgorithm algorithm, int keySize, CipherModeEx mode, byte[] key, byte[] iv)
        {
            Contract.Requires(algorithm != null);
            Contract.Requires(key != null);
            Contract.Requires(iv != null);
            Contract.Requires(keySize == key.Length << 3);

            _algorithm = algorithm;
            _mode = mode;
            algorithm.Key = key;
            algorithm.IV = iv;
        }

        public int BlockSize
        {
            get { return _algorithm.BlockSize >> 3; }
        }

        public byte[] Encrypt(byte[] input)
        {
            using (var ms = new MemoryStream())
            {
                using (var transform = CreateTransform(true))
                {
                    using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Write))
                    {
                        cs.Write(input, 0, input.Length);
                        cs.FlushFinalBlock();

                        return ms.ToArray();
                    }
                }
            }
        }

        public byte[] Decrypt(byte[] input)
        {
            using (var ms = new MemoryStream(input))
            {
                using (var transform = CreateTransform(false))
                {
                    using (var cs = new CryptoStream(ms, transform, CryptoStreamMode.Read))
                    {
                        var output = new byte[input.Length];
                        var outputLength = cs.Read(output, 0, output.Length);

                        Array.Resize(ref output, outputLength);

                        return output;
                    }
                }
            }
        }

        private ICryptoTransform CreateTransform(bool encryptor)
        {
            switch (_mode)
            {
                case CipherModeEx.CBC:
                    _algorithm.Mode = CipherMode.CBC;
                    return encryptor
                        ? _algorithm.CreateEncryptor()
                        : _algorithm.CreateDecryptor();
                case CipherModeEx.CTR:
                    return new CtrModeCryptoTransform(_algorithm, encryptor);
                default:
                    throw new InvalidEnumArgumentException(string.Format("Invalid mode: {0}", _mode));
            }
        }
    }
}
