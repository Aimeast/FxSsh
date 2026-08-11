using System;
using System.Buffers;
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
    /// Server-side reverse port forwarding (RFC 4254 section 7.2).
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

        /// <summary>Bound host the listener actually used (may differ from requested when host was empty).</summary>
        public string BoundAddress { get; }

        /// <summary>Bound port the listener actually used ( RFC 4254: when requested port is 0, return the OS-assigned port).</summary>
        public uint BoundPort { get; private set; }

        /// <summary>Raised (best-effort) when a forwarded channel is torn down because the peer closed it or the listener stopped.</summary>
        public event EventHandler<Channel> ForwardedChannelClosed;

        /// <summary>
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

        public void Start()
        {
            _listener.Start();
            BoundPort = (uint)((IPEndPoint)_listener.LocalEndpoint).Port;
            Log.Info($"Forwarding listener bound at {BoundAddress}:{BoundPort}.");
            _ = AcceptLoopAsync();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await _listener.AcceptSocketAsync(_cts.Token);
                }
                catch (OperationCanceledException) { break; }
                catch (SocketException) { break; }   // listener stopped
                catch (ObjectDisposedException) { break; }

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

        /// <summary>
        /// Wire a forwarded channel to a socket with two async pumps:
        /// channel->socket (send queue consumed by an async sender) and
        /// socket->channel (async receive loop feeding Channel.SendDataAsync).
        /// No thread is blocked on socket I/O.
        /// </summary>
        private async Task BridgeAsync(Channel channel, Socket socket)
        {
            Log.Debug($"Bridge established: channel {channel.ServerChannelId} <-> {socket.RemoteEndPoint}.");
            lock (_bridgeLocker)
                _bridges.Add((channel, socket));

            // The channel DataReceived callback runs on the SSH
            // ConnectionService.MessageLoop task. The queue is bounded
            // (FullMode.Wait), so a blocking Write here is the intended
            // backpressure path: when the local TCP peer is slow, the
            // message loop task pauses, which stops replenishing the SSH
            // receive window and throttles the client's TCP send buffer,
            // instead of growing the queue without limit.
            //
            // The incoming ReadOnlyMemory is a slice over the SSH receive
            // buffer, which is recycled by the next ReceiveMessage on the
            // message-loop task, so we MUST hand the send pump an independent
            // copy. Instead of ToArray()'ing a fresh byte[] per packet (the
            // forwarding hot path's last heap allocation), the copy is made
            // into an ArrayPool rental owned by PooledMemoryOwner, which the
            // send pump disposes after SendAsync - the rental is reused
            // across packets instead of hitting Gen0.
            var sendQueue = System.Threading.Channels.Channel.CreateBounded<IMemoryOwner<byte>>(new BoundedChannelOptions(16)
            {
                SingleReader = true,
                FullMode = BoundedChannelFullMode.Wait,
            });

            channel.DataReceived += (_, data) =>
            {
                var owned = new PooledMemoryOwner(data.Length);
                data.Span.CopyTo(owned.Memory.Span);
                try { sendQueue.Writer.WriteAsync(owned).AsTask().GetAwaiter().GetResult(); }
                catch { owned.Dispose(); }
            };
            channel.CloseReceived += (_, _) =>
            {
                try
                {
                    sendQueue.Writer.TryComplete();
                    if (socket.Connected) socket.Shutdown(SocketShutdown.Send);
                }
                catch { }
            };

            var sendTask = SendLoopAsync(sendQueue.Reader, socket);

            // Socket -> channel pump.
            var buf = new byte[1024 * 32];
            try
            {
                while (socket.Connected && !_cts.IsCancellationRequested)
                {
                    int n;
                    try
                    {
                        n = await socket.ReceiveAsync(buf.AsMemory(), SocketFlags.None, _cts.Token);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (SocketException) { break; }
                    catch (ObjectDisposedException) { break; }

                    if (n <= 0) break;
                    await channel.SendDataAsync(n == buf.Length ? buf : buf[..n]);
                }
            }
            catch
            {
            }
            finally
            {
                channel.SendEof();
                try { socket.Close(); } catch { }

                lock (_bridgeLocker)
                    _bridges.Remove((channel, socket));

                Log.Debug($"Bridge closed: channel {channel.ServerChannelId}.");
                ForwardedChannelClosed?.Invoke(this, channel);
            }

            await sendTask;
        }

        /// <summary>
        /// Serialize socket.SendAsync over the channel->socket queue. Runs as
        /// a single async task so the ConnectionService message loop never
        /// blocks on the local TCP peer. Each pooled buffer is disposed after
        /// SendAsync returns the rental to the pool; a send failure (peer
        /// reset) stops the pump but the finally drains and disposes every
        /// still-queued rental so nothing leaks out of the pool.
        /// </summary>
        private async Task SendLoopAsync(ChannelReader<IMemoryOwner<byte>> sendQueue, Socket socket)
        {
            try
            {
                await foreach (var data in sendQueue.ReadAllAsync(_cts.Token))
                {
                    using (data)
                    {
                        try
                        {
                            if (data.Memory.Length > 0 && socket.Connected)
                                await socket.SendAsync(data.Memory, SocketFlags.None, _cts.Token);
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
                // Dispose every pooled buffer still in the queue. ReadAllAsync
                // stops on cancellation/error, so without this the rentals
                // would be permanently withdrawn from the pool.
                while (sendQueue.TryRead(out var item))
                    item.Dispose();
            }
        }

        public void Dispose()
        {
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

            _cts.Dispose();
        }
    }
}
