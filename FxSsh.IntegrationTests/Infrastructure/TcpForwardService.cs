using System;
using System.Buffers;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Test-infrastructure copy of the SshServerLoader sample's TCP forward
    /// bridge: connects to the local TCP target requested by the peer and
    /// pumps bytes between the socket and the SSH channel (RFC 4254 7).
    /// </summary>
    public class TcpForwardService
    {
        private static readonly BoundedChannelOptions SendChannelOptions = new(16)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        };

        private readonly Socket _socket = new(SocketType.Stream, ProtocolType.Tcp);
        private readonly string _host;
        private readonly int _port;
        private readonly Channel<IMemoryOwner<byte>> _sendChannel = Channel.CreateBounded<IMemoryOwner<byte>>(SendChannelOptions);
        private readonly CancellationTokenSource _cts = new();
        private bool _closed;

        public TcpForwardService(string host, int port, string originatorIP, int originatorPort)
        {
            _host = host;
            _port = port;
        }

        public event EventHandler<byte[]>? DataReceived;

        public event EventHandler? CloseReceived;

        public void Start()
        {
            _ = RunAsync();
        }

        private async Task RunAsync()
        {
            try
            {
                await _socket.ConnectAsync(_host, _port);

                var sendTask = SendLoopAsync();

                var bytes = new byte[1024 * 64];
                while (!_cts.IsCancellationRequested)
                {
                    int read;
                    try
                    {
                        read = await _socket.ReceiveAsync(bytes.AsMemory(), SocketFlags.None, _cts.Token);
                    }
                    catch
                    {
                        break;
                    }

                    if (read <= 0)
                        break;

                    DataReceived?.Invoke(this, bytes.AsSpan(0, read).ToArray());
                }

                CloseReceived?.Invoke(this, EventArgs.Empty);
                Finish();

                await sendTask;
            }
            catch
            {
                OnClose();
            }
        }

        private async Task SendLoopAsync()
        {
            try
            {
                await foreach (var data in _sendChannel.Reader.ReadAllAsync(_cts.Token))
                {
                    using (data)
                    {
                        try
                        {
                            if (data.Memory.Length == 0)
                                continue;
                            await _socket.SendAsync(data.Memory, SocketFlags.None, _cts.Token);
                        }
                        catch
                        {
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Socket closed or canceled.
            }
            finally
            {
                while (_sendChannel.Reader.TryRead(out var item))
                    item.Dispose();
            }
        }

        public void OnData(ReadOnlyMemory<byte> data)
        {
            var owned = new PooledMemoryOwner(data.Length);
            data.Span.CopyTo(owned.Memory.Span);
            try
            {
                _sendChannel.Writer.WriteAsync(owned, _cts.Token).AsTask().GetAwaiter().GetResult();
            }
            catch
            {
                owned.Dispose();
                OnClose();
            }
        }

        public void OnClose()
        {
            _sendChannel.Writer.TryComplete();
            try
            {
                _socket.Shutdown(SocketShutdown.Send);
            }
            catch
            {
            }
        }

        private void Finish()
        {
            if (_closed)
                return;

            _closed = true;
            _cts.Cancel();
            try
            {
                _socket.Close();
            }
            catch
            {
            }
        }
    }
}
