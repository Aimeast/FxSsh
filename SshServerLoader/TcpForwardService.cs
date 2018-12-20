using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SshServerLoader
{
    public class TcpForwardService
    {
        Socket _socket = null;

        public TcpForwardService(string host, int port, string originatorIP, int originatorPort)
        {
            _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _socket.Connect(host, port);
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler CloseReceived;


        public void Start()
        {
            Task.Run(() => MessageLoop());
        }

        public void OnData(byte[] data)
        {
            _socket.Send(data);
        }

        public void OnClose()
        {
            _socket.Shutdown(SocketShutdown.Send);
        }

        private void MessageLoop()
        {
            var bytes = new byte[1024 * 64];
            while (true)
            {
                var len = _socket.Receive(bytes);
                if (len <= 0)
                    break;

                var data = bytes.Length != len
                    ? bytes.Take(len).ToArray()
                    : bytes;
                DataReceived?.Invoke(this, data);
            }
            CloseReceived?.Invoke(this, EventArgs.Empty);
        }
    }
}
