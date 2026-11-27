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
        private readonly object _writeLocker = new();
        private Task _pendingWrites = Task.CompletedTask;
        private bool _closed;
        private int _closeRaised;

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

                RaiseClose();

                // Let the send pump flush every queued byte and close the
                // local send direction before the socket is torn down. Closing
                // first truncates the tail of the client->target stream.
                await sendTask;
                Finish();
            }
            catch
            {
                // A failed local connect (or a mid-stream socket error) must
                // still close the SSH channel, otherwise the forwarded client
                // waits for a CHANNEL_CLOSE that never arrives.
                RaiseClose();
                OnClose();
                Finish();
            }
        }

        private void RaiseClose()
        {
            if (Interlocked.Exchange(ref _closeRaised, 1) != 0)
                return;

            // A failing host handler must not skip the OnClose/Finish teardown
            // that follows this call; otherwise the local socket and the send
            // pump would outlive the SSH channel.
            try { CloseReceived?.Invoke(this, EventArgs.Empty); } catch { }
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

                            // SendAsync may accept fewer bytes than requested;
                            // a partial write must not truncate the stream.
                            var offset = 0;
                            while (offset < data.Memory.Length)
                            {
                                var sent = await _socket.SendAsync(
                                    data.Memory[offset..],
                                    SocketFlags.None,
                                    _cts.Token);
                                if (sent <= 0)
                                    throw new SocketException((int)SocketError.ConnectionReset);
                                offset += sent;
                            }
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

                // The queue is drained (or the pump was canceled): FIN now,
                // after the data, never before it.
                try { _socket.Shutdown(SocketShutdown.Send); } catch { }
            }
        }

        public void OnData(ReadOnlyMemory<byte> data)
        {
            var owned = new PooledMemoryOwner(data.Length);
            data.Span.CopyTo(owned.Memory.Span);

            // Never block the SSH message loop on the local TCP peer: a full
            // queue combined with a full-duplex window stall would deadlock
            // (the loop also has to deliver the WINDOW_ADJUST that drains the
            // outgoing side). Queue asynchronously and let the channel's
            // bounded writer apply backpressure to this copy. Chaining the
            // writes preserves stream order and lets OnClose wait for them.
            lock (_writeLocker)
            {
                _pendingWrites = QueueAfterAsync(_pendingWrites, owned);
            }
        }

        private async Task QueueAfterAsync(Task previous, IMemoryOwner<byte> owned)
        {
            try { await previous.ConfigureAwait(false); } catch { }

            try
            {
                await _sendChannel.Writer.WriteAsync(owned, _cts.Token).ConfigureAwait(false);
            }
            catch
            {
                owned.Dispose();
            }
        }

        public void OnClose()
        {
            // Complete the writer only after every byte accepted from SSH has
            // been enqueued; the send pump then drains the queue and FINs.
            Task pending;
            lock (_writeLocker)
                pending = _pendingWrites;

            _ = CompleteAfterAsync(pending);
        }

        private async Task CompleteAfterAsync(Task pending)
        {
            try { await pending.ConfigureAwait(false); } catch { }
            _sendChannel.Writer.TryComplete();
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
