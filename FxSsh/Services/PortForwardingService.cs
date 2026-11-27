using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using FxSsh.Logging;

namespace FxSsh.Services
{
    /// <summary>
    /// Server-side reverse port forwarding (RFC 4254 section 7).
    ///
    /// Bound to a single (address, port) endpoint requested by the peer via
    /// SSH_MSG_GLOBAL_REQUEST "tcpip-forward". Each inbound TCP connection is
    /// reported back to the peer via SSH_MSG_CHANNEL_OPEN "forwarded-tcpip"
    /// through the supplied channel-open factory; the peer then speaks SSH
    /// channel data into the forwarded socket. Closing the service (via
    /// "cancel-tcpip-forward" or session teardown) stops the listener and
    /// tears down any in-flight forwarded channels.
    ///
    /// The accept loop and both bridge pumps are fully async (AcceptSocketAsync /
    /// ReceiveAsync / SendAsync / Channel.SendDataAsync): no thread is blocked
    /// on socket I/O, so thousands of forwarded connections do not consume a
    /// thread each.
    /// </summary>
    public sealed class PortForwardingService : IDisposable
    {
        private readonly IPEndPoint _endpoint;
        private readonly Func<string, uint, string, uint, Channel> _openForwardedChannel;
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly List<(Channel channel, Socket socket)> _bridges = [];
        private readonly object _bridgeLocker = new();
        private int _disposed;

        /// <summary>Bound host the listener actually used (may differ from requested when host was empty).</summary>
        public string BoundAddress { get; }

        /// <summary>Bound port the listener actually used (RFC 4254: when the requested port is 0, the OS-assigned port).</summary>
        public uint BoundPort { get; private set; }

        /// <summary>Raised (best-effort) when a forwarded channel is torn down because the peer closed it or the listener stopped.</summary>
        public event EventHandler<Channel> ForwardedChannelClosed;

        /// <summary>
        /// Initializes a new instance of the <see cref="PortForwardingService"/> class
        /// for one reverse-forwarded (address, port) endpoint.
        /// </summary>
        /// <param name="address">Bind address as requested by the peer. Empty/null selects IPv4Any.</param>
        /// <param name="port">Bind port. 0 lets the OS choose; the chosen port is exposed via BoundPort.</param>
        /// <param name="openForwardedChannel">Factory that opens an outbound forwarded-tcpip channel
        /// and returns the Channel handle. Receives (boundAddress, boundPort, originatorIP, originatorPort).</param>
        public PortForwardingService(string address, uint port,
            Func<string, uint, string, uint, Channel> openForwardedChannel)
        {
            if (port > ushort.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(port));

            _openForwardedChannel = openForwardedChannel
                ?? throw new ArgumentNullException(nameof(openForwardedChannel));

            var ip = string.IsNullOrEmpty(address) ? IPAddress.Any : IPAddress.Parse(address);
            _endpoint = new IPEndPoint(ip, (int)port);
            BoundAddress = ip.ToString();
            // BoundPort is set after Start() resolves the OS-assigned port.

            _listener = new TcpListener(_endpoint);
        }

        /// <summary>
        /// Starts the TCP listener and its asynchronous accept loop. When the
        /// requested port was 0, the OS-assigned port is published via
        /// <see cref="BoundPort"/> so it can be reported back to the peer.
        /// </summary>
        public void Start()
        {
            _listener.Start();
            BoundPort = (uint)((IPEndPoint)_listener.LocalEndpoint).Port;
            Log.Info($"Forwarding listener bound at {BoundAddress}:{BoundPort}.");
            _ = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    Socket client;
                    try
                    {
                        client = await _listener.AcceptSocketAsync(_cts.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }
                    catch (SocketException ex)
                    {
                        if (_cts.IsCancellationRequested)
                            break;

                        // A transient accept failure (for example EMFILE)
                        // must not permanently disable the listener.
                        Log.Warn($"Forwarding accept failed for {BoundAddress}:{BoundPort}: {ex.Message}");
                        try
                        {
                            await Task.Delay(100, _cts.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        continue;
                    }

                    var remote = (IPEndPoint)client.RemoteEndPoint;

                    // Open an outbound forwarded-tcpip channel to the peer. The
                    // factory is responsible for sending SSH_MSG_CHANNEL_OPEN and
                    // returning the Channel handle. If the peer rejects, drop the
                    // TCP connection silently.
                    Channel channel;
                    try
                    {
                        channel = _openForwardedChannel(BoundAddress, BoundPort,
                            remote.Address.ToString(), (uint)remote.Port);
                    }
                    catch
                    {
                        Log.Warn($"Forwarded channel open failed for {remote}; dropping TCP connection.");
                        try { client.Close(); } catch { }
                        continue;
                    }

                    if (channel == null)
                    {
                        try { client.Close(); } catch { }
                        continue;
                    }

                    _ = BridgeAsync(channel, client);
                }
            }
            catch (ObjectDisposedException)
            {
                // Dispose() stopped the listener while this loop was waiting.
            }
            catch (Exception ex)
            {
                Log.Fail($"Forwarding accept loop failed for {BoundAddress}:{BoundPort}: {ex.Message}");
            }
        }

        /// <summary>
        /// Wire a forwarded channel to a socket with two async pumps:
        /// channel->socket (send queue consumed by an async sender) and
        /// socket->channel (async receive loop feeding Channel.SendDataAsync).
        /// No thread is blocked on socket I/O, and no path blocks the SSH
        /// message loop: when the local TCP peer cannot keep up, the bounded
        /// queue is full and the bridge is torn down instead of stalling the
        /// whole session.
        /// </summary>
        private async Task BridgeAsync(Channel channel, Socket socket)
        {
            // The channel DataReceived callback runs on the SSH
            // ConnectionService.MessageLoop task. The incoming
            // ReadOnlyMemory is a slice over the SSH receive buffer, which is
            // recycled by the next ReceiveMessage, so the bytes are copied
            // into an ArrayPool rental owned by PooledMemoryOwner and disposed
            // by the send pump after SendAsync.
            //
            // The queue is bounded and TryWrite is non-blocking: a slow local
            // TCP peer must not freeze the single SSH message loop (which
            // would stall every other channel too). Data is queued through a
            // serialized pending chain because the SSH window is replenished
            // as soon as OnData returns; the chain's bytes are capped below so
            // a stalled local socket cannot grow it without bound.
            const int MaximumPendingBytes = 8 * 1024 * 1024;
            var pendingBytes = 0L;
            var sendQueue = System.Threading.Channels.Channel.CreateBounded<ChannelDataLease>(new BoundedChannelOptions(16)
            {
                SingleReader = true,
                FullMode = BoundedChannelFullMode.Wait,
            });

            var bridgeClosed = 0;
            void CloseBridge(bool closeChannel = false)
            {
                if (Interlocked.Exchange(ref bridgeClosed, 1) != 0)
                    return;

                sendQueue.Writer.TryComplete();
                try { socket.Shutdown(SocketShutdown.Both); } catch { }
                try { socket.Close(); } catch { }
                if (closeChannel)
                {
                    // Overload abort: tell the peer the channel is gone
                    // instead of leaving it half-open until session teardown.
                    _ = CloseChannelAsync(channel);
                }
            }

            // A force-closed channel (e.g. the peer rejected the forwarded
            // open) will never see a CHANNEL_CLOSE exchange - release the
            // bridged socket so the pump ends instead of lingering forever.
            // Subscribe before anything else can observe the channel: the
            // peer's CHANNEL_OPEN_FAILURE is processed on the message loop
            // and may land before this task even gets scheduled, and
            // ForceClose fires the event synchronously - subscribing later
            // would miss it.
            channel.ForceClosed += (_, _) => CloseBridge();

            if (channel.IsForceClosed)
            {
                // The open was rejected before the subscription above
                // existed, so the handler never ran. Release the socket and
                // skip the bridge entirely; nothing may be written on the
                // channel because the peer already removed it, and newer
                // OpenSSH clients answer packets for a nonexistent channel
                // with a protocol-error disconnect.
                Log.Debug($"Forwarded channel {channel.ServerChannelId} rejected before bridging; dropping the accepted socket.");
                CloseBridge();
                return;
            }

            Log.Debug($"Bridge established: channel {channel.ServerChannelId} <-> {socket.RemoteEndPoint}.");
            lock (_bridgeLocker)
            {
                if (Volatile.Read(ref _disposed) != 0)
                {
                    try { socket.Close(); } catch { }
                    return;
                }
                _bridges.Add((channel, socket));
            }

            // Queue writes asynchronously and in order. The bounded channel
            // absorbs the interval before the send pump drains a chunk; the
            // pending-bytes cap bounds everything that has been accepted from
            // SSH but not yet handed to the local socket.
            var sendLocker = new object();
            var pendingSend = Task.CompletedTask;

            async Task EnqueueAfterAsync(Task previous, ChannelDataLease lease, int length)
            {
                try { await previous.ConfigureAwait(false); } catch { }

                try
                {
                    await sendQueue.Writer.WriteAsync(lease, _cts.Token).ConfigureAwait(false);
                }
                catch
                {
                    // Teardown completed the writer or cancelled the bridge.
                    lease.Dispose();
                }
                finally
                {
                    Interlocked.Add(ref pendingBytes, -length);
                }
            }

            async Task CompleteAfterAsync(Task pending)
            {
                try { await pending.ConfigureAwait(false); } catch { }
                sendQueue.Writer.TryComplete();
            }

            channel.LeaseReceived += (_, lease) =>
            {
                if (Volatile.Read(ref bridgeClosed) != 0 || _cts.IsCancellationRequested)
                {
                    lease.ReleaseIfNotRetained();
                    return;
                }

                var length = lease.Memory.Length;
                if (length == 0)
                {
                    lease.ReleaseIfNotRetained();
                    return;
                }

                var total = Interlocked.Add(ref pendingBytes, length);
                if (total > MaximumPendingBytes)
                {
                    Interlocked.Add(ref pendingBytes, -length);
                    lease.ReleaseIfNotRetained();
                    Log.Warn($"Forwarded channel {channel.ServerChannelId} backlog exceeded {MaximumPendingBytes} bytes; closing the bridge.");
                    CloseBridge(closeChannel: true);
                    return;
                }

                // Take ownership of the pooled receive buffer when possible;
                // a non-owning/test payload gets one pooled copy.
                lease.TryRetainOrCopy(out var owned);
                lock (sendLocker)
                    pendingSend = EnqueueAfterAsync(pendingSend, owned, length);
            };

            channel.CloseReceived += (_, _) =>
            {
                // Stop accepting new channel data only after every byte that
                // was already accepted from SSH has been enqueued; the send
                // pump then drains the queue before the socket is shut down,
                // so the tail of the forwarded stream is never truncated.
                Task pending;
                lock (sendLocker)
                    pending = pendingSend;

                _ = CompleteAfterAsync(pending);
            };

            var sendTask = SendLoopAsync(sendQueue, socket);

            // Socket -> channel pump. The receive buffer is rented from the
            // SSH packet pool and returned once the pump ends, so a server
            // with thousands of forwarded bridges does not hold thousands of
            // dedicated 32 KiB heap arrays.
            const int ReadBufferSize = 1024 * 32;
            var buf = SshBuffers.Packets.Rent(ReadBufferSize);
            try
            {
                while (socket.Connected && !_cts.IsCancellationRequested)
                {
                    int n;
                    try
                    {
                        n = await socket.ReceiveAsync(buf.AsMemory(0, ReadBufferSize), SocketFlags.None, _cts.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (SocketException) { break; }
                    catch (ObjectDisposedException) { break; }

                    if (n <= 0) break;
                    if (Log.IsEnabled(LogLevel.Trace))
                        Log.Trace($"Forwarding {n} bytes socket -> channel {channel.ServerChannelId}.");
                    await channel.SendDataAsync(buf.AsMemory(0, n));
                }
            }
            catch
            {
            }
            finally
            {
                SshBuffers.Packets.Return(buf);
                // No more channel->socket data: wait for every accepted chunk
                // to be enqueued, then let the send pump drain the queue
                // (bounded wait; closing the socket below unblocks a stuck
                // SendAsync) before closing the TCP side and telling the peer
                // this direction is finished.
                Task pending;
                lock (sendLocker)
                    pending = pendingSend;

                try { await CompleteAfterAsync(pending).WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false); } catch { }
                try { await sendTask.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false); } catch { }

                if (Volatile.Read(ref bridgeClosed) == 0)
                {
                    try
                    {
                        await channel.SendEofAsync().WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                    }
                    catch
                    {
                        // The peer window or send gate stayed blocked; closing
                        // the socket below still ends the bridge.
                    }
                }
                try { socket.Shutdown(SocketShutdown.Both); } catch { }
                try { socket.Close(); } catch { }

                lock (_bridgeLocker)
                    _bridges.Remove((channel, socket));

                Log.Debug($"Bridge closed: channel {channel.ServerChannelId}.");
                ForwardedChannelClosed?.Invoke(this, channel);
            }
        }

        private static async Task CloseChannelAsync(Channel channel)
        {
            try
            {
                await channel.SendCloseAsync(1).WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            }
            catch { }
        }

        /// <summary>
        /// Serialize socket.SendAsync over the channel->socket queue. Runs as
        /// a single async task so the ConnectionService message loop never
        /// blocks on the local TCP peer. Each pooled buffer is disposed after
        /// SendAsync returns the rental to the pool; a send failure (peer
        /// reset) stops the pump but the finally drains and disposes every
        /// still-queued rental so nothing leaks out of the pool. Completed
        /// writers are signalled so a producer cannot wait forever.
        /// </summary>
        private async Task SendLoopAsync(System.Threading.Channels.Channel<ChannelDataLease> sendQueue, Socket socket)
        {
            try
            {
                await foreach (var lease in sendQueue.Reader.ReadAllAsync(_cts.Token))
                {
                    using (lease)
                    {
                        try
                        {
                            var memory = lease.Memory;
                            if (memory.Length == 0 || !socket.Connected)
                                continue;

                            // SendAsync may accept fewer bytes than requested;
                            // a partial write must not silently truncate the
                            // forwarded stream.
                            var offset = 0;
                            while (offset < memory.Length)
                            {
                                var sent = await socket.SendAsync(memory[offset..], SocketFlags.None, _cts.Token);
                                if (sent <= 0)
                                    throw new SocketException((int)SocketError.ConnectionReset);
                                offset += sent;
                            }
                        }
                        catch
                        {
                            // Single send failure (peer reset) is tolerated by
                            // stopping the pump; the finally below drains the
                            // remaining queue. Without this inner catch a
                            // failure would kill the whole pump and strand the
                            // queued rentals.
                            break;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception)
            {
                // ReadAllAsync failed (socket closed/canceled); drain below.
            }
            finally
            {
                // Unblock any producer waiting on the bounded queue: the pump
                // is gone, so further writes cannot be drained.
                sendQueue.Writer.TryComplete();

                // Dispose every pooled buffer still in the queue. ReadAllAsync
                // stops on cancellation/error, so without this the rentals
                // would be permanently withdrawn from the pool.
                while (sendQueue.Reader.TryRead(out var item))
                    item.Dispose();
            }
        }

        /// <summary>
        /// Stops the listener and closes every bridged TCP socket. The SSH
        /// side of each forwarded channel is left to be torn down by the peer
        /// or by session teardown.
        /// </summary>
        public void Dispose()
        {
            // Atomic compare-and-set: concurrent teardown (session CloseService
            // plus cancel-tcpip-forward) must not run the cleanup twice or
            // dispose the CTS while bridge pumps still await its token.
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            Log.Debug($"Forwarding listener {BoundAddress}:{BoundPort} stopping.");
            _cts.Cancel();
            try { _listener.Stop(); } catch { }

            lock (_bridgeLocker)
            {
                foreach (var (channel, socket) in _bridges.ToArray())
                {
                    try { socket.Close(); } catch { }
                    // channel is torn down by the peer or CloseService; do not ForceClose here.
                }
                _bridges.Clear();
            }

            // _cts is intentionally not disposed: bridge pump tasks may still
            // be unwinding from the cancellation and would throw
            // ObjectDisposedException while unregistering their token.
        }
    }
}
