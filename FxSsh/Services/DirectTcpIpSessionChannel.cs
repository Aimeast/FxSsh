
using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh.Messages.Connection;

namespace FxSsh.Services
{
    public class DirectTcpIpSessionChannel : SessionChannel
    {
        private System.Threading.CancellationTokenSource cancel;
        private DirectTcpIpMessage message;
        private TcpClient cl;

        public DirectTcpIpSessionChannel(ConnectionService connectionService, DirectTcpIpMessage message, uint id)
            : base(connectionService, message.SenderChannel, message.InitialWindowSize, message.MaximumPacketSize, id)
        {
            this.message = message;
            this.DataReceived += this.DirectTcpIpSessionChannel_DataReceived;
            this.EofReceived += this.DirectTcpIpSessionChannel_EofReceived;
            this.CloseReceived += this.DirectTcpIpSessionChannel_CloseReceived;
        }

        private void DirectTcpIpSessionChannel_CloseReceived(object sender, EventArgs e)
        {
            base.SendClose(0);
            cancel?.Cancel();
            cl?.Close();
            cl = null;
        }

        private void DirectTcpIpSessionChannel_EofReceived(object sender, EventArgs e)
        {
            cl.GetStream().Flush();
            cl.GetStream().Close();
        }

        private void DirectTcpIpSessionChannel_DataReceived(object sender, byte[] e)
        {
            cl.GetStream().Write(e, 0, e.Length);
        }

        public void ConnectToTarget()
        {
            this.cl = new TcpClient();
            cl.Connect(this.message.HostToConnect, (int)this.message.PortToConnect);
            cancel = new System.Threading.CancellationTokenSource();
            Task.Run(ReadAsync);
        }

        private async Task ReadAsync()
        {
            byte[] buffer = new byte[Math.Max(1024, Math.Min(this.message.MaximumPacketSize, 64 * 1024))];

            while (true)
            {
                try
                {
                    int read = await cl.GetStream().ReadAsync(buffer, 0, buffer.Length, cancel.Token);

                    if (cancel.Token.IsCancellationRequested)
                    {
                        return;
                    }

                    if (read <= 0)
                    {
                        break;
                    }

                    this.SendData(buffer, 0, read);
                }
                catch (Exception)
                {
                    break;
                }
            }
            this.SendEof();
        }
    }
}
