using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Text;

namespace FxSsh.Services
{
    public class KeyExchangeArgs
    {
        public KeyExchangeArgs(Session s)
        {
            this.Session = s;
        }

        public Session Session { get; private set; }

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
    }
}
