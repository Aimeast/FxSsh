using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Algorithms.Catalog;
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

        /// <summary>
        /// Per-server pluggable algorithm registry, seeded from the
        /// <see cref="AlgorithmRegistry"/> defaults supported on this platform.
        /// Mutate (Add/Remove) the exposed per-category collections to plug in
        /// extra algorithms (e.g. curve25519-sha256 or legacy algos) per server,
        /// without forking the library. Mutations are reflected in the KEXINIT
        /// name-lists and in negotiation.
        /// </summary>
        public AlgorithmSelection Algorithms { get; } = new();

        public event EventHandler<Session> ConnectionAccepted;
        public event EventHandler<Exception> ExceptionRaised;

        public void Start() => StartAsync().GetAwaiter().GetResult();
        public void Stop() => StopAsync().GetAwaiter().GetResult();

        public Task StartAsync(CancellationToken cancellationToken = default)
        {
            CheckDisposed();
            if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
                throw new InvalidOperationException("The server is already started.");

            Algorithms.BuildSelection(LogCipherSuites);

            Log.Info($"SSH server listening on {StartingInfo.LocalAddress}:{StartingInfo.Port}.");
            _listenser = StartingInfo.LocalAddress == IPAddress.IPv6Any
                ? TcpListener.Create(StartingInfo.Port) // dual stack
                : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
            _listenser.ExclusiveAddressUse = false;
            _listenser.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listenser.Start();

            _ = AcceptConnectionsAsync(cancellationToken);

            return Task.CompletedTask;
        }

        private void LogCipherSuites(AlgorithmCatalog catalog)
        {
            if (Log.IsEnabled(LogLevel.Info))
            {
                var hostKey = catalog.HostKeyCollection.Names.Intersect(_hostKey.Keys);
                var kex = catalog.KeyExchangeCollection.Names;
                var cipher = catalog.EncryptionCollection.Names;
                var hmac = catalog.HmacCollection.Names;
                var compression = catalog.CompressionCollection.Names;

                Log.Info("Server cipher suites: " +
                    $"hostkey=[{string.Join(",", hostKey)}], kex=[{string.Join(",", kex)}], " +
                    $"cipher=[{string.Join(",", cipher)}], hmac=[{string.Join(",", hmac)}], " +
                    $"compression=[{string.Join(",", compression)}].");
            }

            if (Log.IsEnabled(LogLevel.Warn))
            {
                var warn = LogWarnOnTag(catalog, AlgorithmTag.Obsolete);
                if (warn.Length > 0)
                    Log.Warn("Enabled obsolete algorithms: " + warn);
                warn = LogWarnOnTag(catalog, AlgorithmTag.Custom);
                if (warn.Length > 0)
                    Log.Warn("Imported custom algorithms: " + warn);
            }
        }

        private string LogWarnOnTag(AlgorithmCatalog catalog, AlgorithmTag tag)
        {
            var result = "";
            var str = string.Join(",", catalog.HostKeyCollection.Where(x => x.Tag == tag).Select(x => x.Name));
            if (str.Length > 0) result += $"hostkey=[{str}].";
            str = string.Join(",", catalog.KeyExchangeCollection.Where(x => x.Tag == tag).Select(x => x.Name));
            if (str.Length > 0) result += $"kex=[{str}].";
            str = string.Join(",", catalog.EncryptionCollection.Where(x => x.Tag == tag).Select(x => x.Name));
            if (str.Length > 0) result += $"cipher=[{str}].";
            str = string.Join(",", catalog.HmacCollection.Where(x => x.Tag == tag).Select(x => x.Name));
            if (str.Length > 0) result += $"hmac=[{str}].";
            str = string.Join(",", catalog.CompressionCollection.Where(x => x.Tag == tag).Select(x => x.Name));
            if (str.Length > 0) result += $"compression=[{str}].";
            return result.TrimEnd('.');
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
            var session = new Session(socket, _hostKey, StartingInfo.ServerBanner, Algorithms);

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
            if (Volatile.Read(ref _isDisposed) == 1)
                return;
            await StopAsync();
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
                GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            if (Volatile.Read(ref _isDisposed) == 1)
                return;
            Stop();
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
                GC.SuppressFinalize(this);
        }
        #endregion
    }
}
