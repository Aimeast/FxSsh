using System;
using System.Buffers;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh;

namespace SshServerLoader
{
    /// <summary>
    /// Client side of SSH "direct-tcpip" forwarding: the socket that connects
    /// to the local TCP target requested by the peer. Both pumps are async
    /// (ConnectAsync / ReceiveAsync / SendAsync) and the SSH->target data path
    /// is a BOUNDED Channel drained by a single async sender, so no thread is
    /// blocked on socket I/O and memory is capped even when the local peer
    /// consumes slowly. When the queue is full, OnData blocks the SSH message
    /// loop task (which stops replenishing the SSH receive window), so
    /// backpressure propagates to the client's TCP send buffer instead of
    /// growing the queue without limit.
    /// </summary>
    public class TcpForwardService
    {
        // Bounded queue: at most 16 in-flight 64KiB chunks (~1 MiB) per
        // forward, so a slow local peer cannot balloon memory. FullMode.Wait
        // makes Writer.Write block (backpressure) instead of dropping data.
        // Elements are ArrayPool rentals (PooledMemoryOwner) so the inbound
        // copy never allocates a fresh byte[] per packet.
        private static readonly BoundedChannelOptions SendChannelOptions = new(16)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        };

        private Socket _socket;
        private string _host;
        private int _port;
        private readonly Channel<IMemoryOwner<byte>> _sendChannel = Channel.CreateBounded<IMemoryOwner<byte>>(SendChannelOptions);
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
                            // Single send failure (peer reset) stops the pump;
                            // the finally below drains the remaining queue so
                            // no PooledMemoryOwner rental is stranded.
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Socket closed or canceled; drain below.
            }
            finally
            {
                // Dispose every pooled buffer still in the queue. ReadAllAsync
                // stops on cancellation/error, so without this the rentals
                // would be permanently withdrawn from the pool.
                while (_sendChannel.Reader.TryRead(out var item))
                    item.Dispose();
            }
        }

        /// <summary>
        /// Called on the SSH ConnectionService.MessageLoop task. Must never
        /// block that task indefinitely: the SSH receive loop and window
        /// adjustments share it. The queue is bounded (FullMode.Wait), so a
        /// blocking Write here is the intended backpressure path - when the
        /// local TCP peer is slow, the message loop task pauses, which stops
        /// replenishing the SSH receive window and throttles the client's TCP
        /// send buffer, instead of growing the queue without limit.
        /// Cancellation (socket closed / session teardown) unblocks the write.
        /// </summary>
        /// <param name="data">Slice over the SSH receive buffer; the send pump runs asynchronously so we copy it into the queue rather than retain the slice past the callback's return.</param>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            // Copy into an ArrayPool rental (PooledMemoryOwner) instead of a
            // fresh byte[] per packet; the send pump disposes it after SendAsync.
            var owned = new PooledMemoryOwner(data.Length);
            data.Span.CopyTo(owned.Memory.Span);
            try
            {
                // Synchronous wait on the bounded channel: the message loop
                // task has no SynchronizationContext, so GetAwaiter().GetResult()
                // safely blocks until the send pump frees a slot (backpressure)
                // or the token is cancelled (teardown).
                _sendChannel.Writer.WriteAsync(owned, _cts.Token).AsTask().GetAwaiter().GetResult();
            }
            catch (ChannelClosedException)
            {
                owned.Dispose();
                OnClose();
            }
            catch (OperationCanceledException)
            {
                owned.Dispose();
                OnClose();
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
