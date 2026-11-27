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
    /// consumes slowly. When the queue is full, OnData queues asynchronously:
    /// it never blocks the SSH message loop, which must stay free to deliver
    /// the WINDOW_ADJUST that lets the opposite direction drain. Blocking the
    /// loop here deadlocks a full-duplex stream once both windows are full.
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
        private readonly object _writeLocker = new();
        private Task _pendingWrites = Task.CompletedTask;
        private long _pendingBytes;
        private volatile bool _closed;
        private int _closeRaised;

        // Cap on bytes accepted from SSH but not yet handed to the local
        // socket. The channel bound alone does not bound the serialized wait
        // chain in front of it; without this cap a stalled target could grow
        // memory without limit.
        private const int MaximumPendingBytes = 8 * 1024 * 1024;

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

                // The queue is drained (or the pump was canceled): FIN now,
                // after the data, never before it.
                try { _socket.Shutdown(SocketShutdown.Send); } catch { }
            }
        }

        /// <summary>
        /// Called on the SSH ConnectionService.MessageLoop task. Must never
        /// block that task: the SSH receive loop and window adjustments share
        /// it, and a full queue plus a full-duplex window stall would deadlock
        /// (the loop also has to deliver the WINDOW_ADJUST that drains the
        /// opposite direction). The bounded writer applies backpressure to
        /// this asynchronous copy instead.
        /// </summary>
        /// <param name="data">Slice over the SSH receive buffer; the send pump runs asynchronously so we copy it into the queue rather than retain the slice past the callback's return.</param>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0 || _closed || _cts.IsCancellationRequested)
                return;

            if (Interlocked.Add(ref _pendingBytes, data.Length) > MaximumPendingBytes)
            {
                Interlocked.Add(ref _pendingBytes, -data.Length);
                // Fail closed under sustained backpressure instead of letting
                // the wait chain grow: tell the peer and release the socket.
                RaiseClose();
                Finish();
                return;
            }

            // Copy into an ArrayPool rental (PooledMemoryOwner) instead of a
            // fresh byte[] per packet; the send pump disposes it after SendAsync.
            // Chaining the writes preserves stream order and lets OnClose wait
            // for every accepted byte before completing the queue.
            var owned = new PooledMemoryOwner(data.Length);
            data.Span.CopyTo(owned.Memory.Span);
            lock (_writeLocker)
            {
                _pendingWrites = QueueAfterAsync(_pendingWrites, owned, data.Length);
            }
        }

        private async Task QueueAfterAsync(Task previous, IMemoryOwner<byte> owned, int length)
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
            finally
            {
                Interlocked.Add(ref _pendingBytes, -length);
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
            try { _socket.Close(); } catch { }
        }
    }
}
