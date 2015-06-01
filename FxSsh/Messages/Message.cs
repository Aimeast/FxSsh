using System;
using System.Diagnostics.Contracts;

namespace SshNet.Messages
{
    public abstract class Message
    {
        protected abstract byte MessageType { get; }

        protected byte[] RawBytes { get; set; }

        public void Load(byte[] bytes)
        {
            Contract.Requires(bytes != null);

            RawBytes = bytes;
            using (var worker = new SshDataWorker(bytes))
            {
                var number = worker.ReadByte();
                if (number != MessageType)
                    throw new ArgumentException(string.Format("Message type {0} is not valid.", number));

                OnLoad(worker);
            }
        }

        public byte[] GetPacket()
        {
            using (var worker = new SshDataWorker())
            {
                worker.Write(MessageType);

                OnGetPacket(worker);

                return worker.ToByteArray();
            }
        }

        public virtual void LoadFrom(Message message)
        {
            Contract.Requires(message != null);

            Load(message.RawBytes);
        }

        protected virtual void OnLoad(SshDataWorker reader)
        {
            Contract.Requires(reader != null);

            throw new NotSupportedException();
        }

        protected virtual void OnGetPacket(SshDataWorker writer)
        {
            Contract.Requires(writer != null);

            throw new NotSupportedException();
        }
    }
}
