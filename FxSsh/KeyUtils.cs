using FxSsh.Algorithms;
using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace FxSsh
{
    public static class KeyUtils
    {
        public static string GetFingerprint(string sshkey)
        {
            Contract.Requires(sshkey != null);

            using (var md5 = new MD5CryptoServiceProvider())
            {
                var bytes = Convert.FromBase64String(sshkey);
                bytes = md5.ComputeHash(bytes);
                return BitConverter.ToString(bytes).Replace('-', ':');
            }
        }

        private static PublicKeyAlgorithm GetKeyAlgorithm(string type)
        {
            Contract.Requires(type != null);

            switch (type)
            {
                case "ssh-rsa":
                    return new RsaKey();
                case "ssh-dss":
                    return new DssKey();
                default:
                    throw new ArgumentOutOfRangeException("type");
            }
        }

        public static string GeneratePrivateKey(string type)
        {
            Contract.Requires(type != null);

            var alg = GetKeyAlgorithm(type);
            var bytes = alg.ExportKey();
            return Convert.ToBase64String(bytes);
        }

        public static string[] SupportedAlgorithms
        {
            get { return new string[] { "ssh-rsa", "ssh-dss" }; }
        }
    }
}
