using System;
using System.Linq;
using System.Text;

namespace SshNet.Messages.Userauth
{
    public class PublicKeyRequestMessage : RequestMessage
    {
        public bool HasSignature { get; private set; }
        public string KeyAlgorithmName { get; private set; }
        public byte[] PublicKey { get; private set; }
        public byte[] Signature { get; private set; }

        public byte[] PayloadWithoutSignature { get; private set; }

        public override void Load(byte[] bytes)
        {
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                Username = worker.ReadString(Encoding.UTF8);
                ServiceName = worker.ReadString(Encoding.ASCII);
                MethodName = worker.ReadString(Encoding.ASCII); // publickey
                HasSignature = worker.ReadBoolean();
                KeyAlgorithmName = worker.ReadString(Encoding.ASCII);
                PublicKey = worker.ReadBinary();

                if (HasSignature)
                {
                    Signature = worker.ReadBinary();
                    PayloadWithoutSignature = bytes.Take(bytes.Length - Signature.Length - 5).ToArray();
                }
            }
        }
    }
}
