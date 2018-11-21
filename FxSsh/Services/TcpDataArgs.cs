using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class TcpDataArgs
    {
        public TcpDataArgs(byte[] data)
        {
            Contract.Requires(data != null);

            Data = data;
        }

        public byte[] Data { get; set; }
        public byte[] Response { get; set; }
    }
}
