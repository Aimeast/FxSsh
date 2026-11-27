using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Loopback TCP echo server with one concurrent handler per connection.
    /// Tests use it as the target of direct-tcpip/forwarded-tcpip channels so
    /// several forwarded streams can run at the same time.
    /// </summary>
    internal sealed class EchoServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _acceptLoop;

        private EchoServer(TcpListener listener)
        {
            _listener = listener;
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            _acceptLoop = AcceptLoopAsync();
        }

        public int Port { get; }

        public static EchoServer Start()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return new EchoServer(listener);
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await _listener.AcceptSocketAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                _ = HandleClientAsync(client);
            }
        }

        private async Task HandleClientAsync(Socket client)
        {
            using (client)
            {
                var buffer = new byte[64 * 1024];
                try
                {
                    while (!_cts.IsCancellationRequested)
                    {
                        var read = await client.ReceiveAsync(buffer, SocketFlags.None, _cts.Token).ConfigureAwait(false);
                        if (read <= 0)
                            break;

                        var offset = 0;
                        while (offset < read)
                        {
                            offset += await client.SendAsync(
                                buffer.AsMemory(offset, read - offset),
                                SocketFlags.None,
                                _cts.Token).ConfigureAwait(false);
                        }
                    }
                }
                catch
                {
                    // Peer reset, test teardown, or cancellation.
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { await _acceptLoop.ConfigureAwait(false); } catch { }
            _cts.Dispose();
        }
    }
}
