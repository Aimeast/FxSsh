using System;
using System.Security.Cryptography;
using System.Text;

namespace SshNet.Messages
{
    [Message("SSH_MSG_KEXINIT", MessageNumber)]
    public class KeyExchangeInitMessage : Message
    {
        private const byte MessageNumber = 20;

        private static readonly RandomNumberGenerator _rng = new RNGCryptoServiceProvider();

        public KeyExchangeInitMessage()
        {
            Cookie = new byte[16];
            _rng.GetBytes(Cookie);
        }

        public byte[] Cookie { get; private set; }

        public string[] KeyExchangeAlgorithms { get; set; }

        public string[] ServerHostKeyAlgorithms { get; set; }

        public string[] EncryptionAlgorithmsClientToServer { get; set; }

        public string[] EncryptionAlgorithmsServerToClient { get; set; }

        public string[] MacAlgorithmsClientToServer { get; set; }

        public string[] MacAlgorithmsServerToClient { get; set; }

        public string[] CompressionAlgorithmsClientToServer { get; set; }

        public string[] CompressionAlgorithmsServerToClient { get; set; }

        public string[] LanguagesClientToServer { get; set; }

        public string[] LanguagesServerToClient { get; set; }

        public bool FirstKexPacketFollows { get; set; }

        public uint Reserved { get; set; }

        public override void Load(byte[] bytes)
        {
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageNumber)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                Cookie = worker.ReadBinary(16);
                KeyExchangeAlgorithms = worker.ReadString(Encoding.UTF8).Split(',');
                ServerHostKeyAlgorithms = worker.ReadString(Encoding.UTF8).Split(',');
                EncryptionAlgorithmsClientToServer = worker.ReadString(Encoding.UTF8).Split(',');
                EncryptionAlgorithmsServerToClient = worker.ReadString(Encoding.UTF8).Split(',');
                MacAlgorithmsClientToServer = worker.ReadString(Encoding.UTF8).Split(',');
                MacAlgorithmsServerToClient = worker.ReadString(Encoding.UTF8).Split(',');
                CompressionAlgorithmsClientToServer = worker.ReadString(Encoding.UTF8).Split(',');
                CompressionAlgorithmsServerToClient = worker.ReadString(Encoding.UTF8).Split(',');
                LanguagesClientToServer = worker.ReadString(Encoding.UTF8).Split(',');
                LanguagesServerToClient = worker.ReadString(Encoding.UTF8).Split(',');
                FirstKexPacketFollows = worker.ReadBoolean();
                Reserved = worker.ReadUInt32();
            }
        }

        public override byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageNumber);
                worker.Write(Cookie);
                worker.Write(string.Join(",", KeyExchangeAlgorithms), Encoding.UTF8);
                worker.Write(string.Join(",", ServerHostKeyAlgorithms), Encoding.UTF8);
                worker.Write(string.Join(",", EncryptionAlgorithmsClientToServer), Encoding.UTF8);
                worker.Write(string.Join(",", EncryptionAlgorithmsServerToClient), Encoding.UTF8);
                worker.Write(string.Join(",", MacAlgorithmsClientToServer), Encoding.UTF8);
                worker.Write(string.Join(",", MacAlgorithmsServerToClient), Encoding.UTF8);
                worker.Write(string.Join(",", CompressionAlgorithmsClientToServer), Encoding.UTF8);
                worker.Write(string.Join(",", CompressionAlgorithmsServerToClient), Encoding.UTF8);
                worker.Write(string.Join(",", LanguagesClientToServer), Encoding.UTF8);
                worker.Write(string.Join(",", LanguagesServerToClient), Encoding.UTF8);
                worker.Write(FirstKexPacketFollows);
                worker.Write(Reserved);

                return worker.ToArray();
            }
        }
    }
}
