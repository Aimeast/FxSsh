using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Logging;

namespace FxSsh
{
    public class SshServer : IDisposable, IAsyncDisposable
    {
        private readonly ConcurrentDictionary<long, Session> _sessions = [];
        private readonly Dictionary<string, string> _hostKey = [];

        private int _isDisposed;
        private int _started;

        private TcpListener _listenser = null;

        public SshServer()
            : this(new StartingInfo())
        { }

        public SshServer(StartingInfo info)
        {
            ArgumentNullException.ThrowIfNull(info);

            StartingInfo = info;
        }

        public StartingInfo StartingInfo { get; private set; }

        public event EventHandler<Session> ConnectionAccepted;
        public event EventHandler<Exception> ExceptionRaised;

        public void Start() => StartAsync().GetAwaiter().GetResult();
        public void Stop() => StopAsync().GetAwaiter().GetResult();

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
                throw new InvalidOperationException("The server is already started.");

            _listenser = StartingInfo.LocalAddress == IPAddress.IPv6Any
                ? TcpListener.Create(StartingInfo.Port) // dual stack
                : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
            _listenser.ExclusiveAddressUse = false;
            _listenser.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listenser.Start();

            Log.Info($"SSH server listening on {StartingInfo.LocalAddress}:{StartingInfo.Port}.");

            _ = AcceptConnectionsAsync(cancellationToken);

            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            CheckDisposed();
            if (Interlocked.Exchange(ref _started, 0) == 0)
                return;

            _listenser.Stop();

            Log.Info("SSH server stopped.");

            var sessionsToDisconnect = _sessions.Values.ToArray();
            _sessions.Clear();

            var disconnectTasks = sessionsToDisconnect
                .Select(session => session.DisconnectAsync())
                .ToArray();

            await Task.WhenAll(disconnectTasks);
        }

        public void AddHostKey(string type, string xml)
        {
            ArgumentNullException.ThrowIfNull(type);
            ArgumentNullException.ThrowIfNull(xml);

            if (!_hostKey.ContainsKey(type))
                _hostKey.Add(type, xml);
        }

        /// <summary>
        /// Accept loop: awaits AcceptSocketAsync (never blocks a thread) and
        /// dispatches each inbound connection to HandleConnectionAsync, which
        /// runs the session's async pumps. The accept task is fire-and-forget
        /// from StartAsync; it exits when the listener is stopped.
        /// </summary>
        private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
        {
            while (Volatile.Read(ref _started) == 1)
            {
                try
                {
                    var socket = await _listenser.AcceptSocketAsync(cancellationToken);
                    _ = HandleConnectionAsync(socket, cancellationToken);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (Volatile.Read(ref _started) == 1)
                        Log.Fail("Listener accept failed.", ex);
                }
            }
        }

        /// <summary>
        /// Per-connection handler: create the Session, register it, then drive
        /// the session's async protocol pumps to completion. No thread is
        /// created per connection - the session's FillPipeAsync /
        /// ProcessPipeAsync / send pump all run as async tasks on the thread
        /// pool, parking on sockets, pipes, and channels instead of blocking.
        /// </summary>
        private async Task HandleConnectionAsync(Socket socket, CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _started) == 0)
            {
                socket.Dispose();
                return;
            }

            var remote = socket.RemoteEndPoint?.ToString() ?? "?";
            var session = new Session(socket, _hostKey, StartingInfo.ServerBanner);

            session.Disconnected += (ss, ee) => _sessions.TryRemove(session.Id, out _);

            _sessions.TryAdd(session.Id, session);

            try
            {
                Log.Info($"Session accepted from {remote}.");
                ConnectionAccepted?.Invoke(this, session);
                Log.Debug($"Session {remote} establishing protocol...");
                await session.StartAsync(cancellationToken);
            }
            catch (SshConnectionException ex)
            {
                if (ex.DisconnectReason == DisconnectReason.ConnectionLost)
                {
                    // Peer closed/reset the TCP connection (e.g. normal
                    // exit after our channel teardown) - not an error.
                    Log.Debug($"Session {remote} connection closed: {ex.Message}");
                }
                else
                {
                    Log.Warn($"Session {remote} aborted: {ex.Message}");
                }

                await session.DisconnectAsync(ex.DisconnectReason, ex.Message);
                ExceptionRaised?.Invoke(this, ex);
            }
            catch (Exception ex)
            {
                Log.Fail($"Session {remote} failed.", ex);
                await session.DisconnectAsync();
                ExceptionRaised?.Invoke(this, ex);
            }
        }

        private void CheckDisposed()
        {
            if (Volatile.Read(ref _isDisposed) == 1)
                throw new ObjectDisposedException(GetType().FullName);
        }

        #region IDisposable
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
            {
                await StopAsync();
                GC.SuppressFinalize(this);
            }
        }

        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
            {
                Stop();
                GC.SuppressFinalize(this);
            }
        }
        #endregion
    }
}
