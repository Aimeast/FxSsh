using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace SshServerLoader
{
    /// <summary>
    /// Client side of SSH "direct-tcpip" forwarding: the socket that connects
    /// to the local TCP target requested by the peer. Both pumps are async
    /// (ConnectAsync / ReceiveAsync / SendAsync) and the SSH->target data path
    /// is a Channel consumed by a single async sender, so no thread is blocked
    /// on socket I/O - the forwarding channel is fully async like
    /// PortForwardingService on the reverse-forward side.
    /// </summary>
    public class TcpForwardService
    {
        private Socket _socket;
        private string _host;
        private int _port;
        private readonly Channel<byte[]> _sendChannel =
            Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true });
        private readonly CancellationTokenSource _cts = new();
        private bool _closed;

        public TcpForwardService(string host, int port, string originatorIP, int originatorPort)
        {
            _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            _host = host;
            _port = port;
        }

        // DataReceived fires on the async socket->SSH pump task. The payload
        // is an independent copy (ToArray) because the pump reuses its read
        // buffer on the next ReceiveAsync - the async consumer may still be
        // awaiting Channel.SendDataAsync when that happens, so a zero-copy
        // slice would alias recycled memory.
        public event EventHandler<byte[]> DataReceived;
        public event EventHandler CloseReceived;

        public void Start()
        {
            _ = RunAsync();
        }

        private async Task RunAsync()
        {
            try
            {
                await _socket.ConnectAsync(_host, _port);

                // Dedicated async send pump: serializes socket.SendAsync so
                // the SSH message loop task never blocks on the local TCP peer.
                var sendTask = SendLoopAsync();

                var bytes = new byte[1024 * 64];
                while (!_cts.IsCancellationRequested)
                {
                    int n;
                    try
                    {
                        n = await _socket.ReceiveAsync(bytes.AsMemory(), SocketFlags.None, _cts.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (SocketException) { break; }
                    catch (ObjectDisposedException) { break; }

                    if (n <= 0) break;
                    DataReceived?.Invoke(this, bytes.AsSpan(0, n).ToArray());
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
                    if (data.Length == 0)
                        continue;
                    await _socket.SendAsync(data, SocketFlags.None, _cts.Token);
                }
            }
            catch
            {
                // Socket closed or canceled; nothing to do.
            }
        }

        /// <summary>
        /// Called on the SSH ConnectionService.MessageLoop task. Must never
        /// block that task: the SSH receive loop and window adjustments share
        /// it, so a blocking socket send here would stall the peer's upload
        /// (its send window is replenished by the same task). Instead the
        /// data is queued and flushed by the async send pump.
        /// </summary>
        /// <param name="data">Slice over the SSH receive buffer; the send pump runs asynchronously so we copy it into the queue rather than retain the slice past the callback's return.</param>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            try
            {
                _sendChannel.Writer.TryWrite(data.ToArray());
            }
            catch
            {
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
            catch { }
        }

        private void Finish()
        {
            if (_closed)
                return;
            _closed = true;

            _cts.Cancel();
            try { _socket.Close(); } catch { }
        }
    }
}
