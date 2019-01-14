using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SshServerLoader
{
    public class TcpForwardService
    {
        private Socket _socket;
        private string _host;
        private int _port;
        private bool _connected;
        private List<byte> _blocked;

        public TcpForwardService(string host, int port, string originatorIP, int originatorPort)
        {
            _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _host = host;
            _port = port;
            _connected = false;
            _blocked = new List<byte>();
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler CloseReceived;

        public void Start()
        {
            Task.Run(() =>
            {
                try
                {
                    MessageLoop();
                }
                catch
                {
                    OnClose();
                }
            });
        }

        public void OnData(byte[] data)
        {
            try
            {
                if (_connected)
                {
                    if (_blocked.Count > 0)
                    {
                        _socket.Send(_blocked.ToArray());
                        _blocked.Clear();
                    }
                    _socket.Send(data);
                }
                else
                {
                    _blocked.AddRange(data);
                }
            }
            catch
            {
                OnClose();
            }
        }

        public void OnClose()
        {
            try
            {
                _socket.Shutdown(SocketShutdown.Send);
            }
            catch { }
        }

        private void MessageLoop()
        {
            _socket.Connect(_host, _port);
            _connected = true;
            OnData(new byte[0]);
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
