using System;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    public class PublicKeyRequestMessage : RequestMessage
    {
        public bool HasSignature { get; private set; }
        public string KeyAlgorithmName { get; private set; }
        public byte[] PublicKey { get; private set; }
        public ReadOnlyMemory<byte> Signature { get; private set; }

        public ReadOnlyMemory<byte> PayloadWithoutSignature { get; private set; }

        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "publickey")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));

            HasSignature = reader.ReadBoolean();
            KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
            PublicKey = reader.ReadBinary();

            if (HasSignature)
            {
                Signature = reader.ReadBinaryAsMemory();
                PayloadWithoutSignature = RawBytes[..(RawBytes.Length - Signature.Length - 5)];
            }
        }
    }
}
