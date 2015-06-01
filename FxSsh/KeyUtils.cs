using System;
using System.Security.Cryptography;

namespace FxSsh
{
    public static class KeyUtils
    {
        public static string GetFingerprint(string sshkey)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                var bytes = Convert.FromBase64String(sshkey);
                bytes = md5.ComputeHash(bytes);
                return BitConverter.ToString(bytes).Replace('-', ':');
            }
        }

        private static AsymmetricAlgorithm GetAsymmetricAlgorithm(string type)
        {
            switch (type)
            {
                case "ssh-rsa":
                    return new RSACryptoServiceProvider();
                case "ssh-dss":
                    return new DSACryptoServiceProvider();
                default:
                    throw new ArgumentOutOfRangeException("type");
            }
        }

        public static string GeneratePrivateKey(string type)
        {
            var alg = GetAsymmetricAlgorithm(type);
            return alg.ToXmlString(true);
        }
    }
}
