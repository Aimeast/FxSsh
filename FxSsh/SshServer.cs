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
    /// <summary>
    /// Represents an SSH server that listens on a TCP endpoint and runs a
    /// <see cref="Session"/> for every accepted client. Register host keys
    /// with <see cref="AddHostKey(string, string)"/>, optionally adjust
    /// <see cref="Algorithms"/>, then call <see cref="Start"/> or
    /// <see cref="StartAsync(CancellationToken)"/> to begin accepting
    /// connections.
    /// </summary>
    public class SshServer : IDisposable, IAsyncDisposable
    {
        private readonly ConcurrentDictionary<long, Session> _sessions = [];
        private readonly Dictionary<string, string> _hostKey = [];

        private int _isDisposed;
        private int _started;

        private TcpListener _listenser = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="SshServer"/> class with
        /// the default <see cref="StartingInfo"/>.
        /// </summary>
        public SshServer()
            : this(new StartingInfo())
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SshServer"/> class with
        /// the specified starting information.
        /// </summary>
        /// <param name="info">The local address, port, and server banner to use.</param>
        public SshServer(StartingInfo info)
        {
            ArgumentNullException.ThrowIfNull(info);

            StartingInfo = info;
        }

        /// <summary>
        /// Gets the starting information this server was created with: the
        /// local address and port to bind, and the protocol version banner to
        /// present to clients.
        /// </summary>
        public StartingInfo StartingInfo { get; private set; }

        /// <summary>
        /// Per-server pluggable algorithm registry, seeded with the
        /// <see cref="AlgorithmCatalog"/> defaults supported on this platform.
        /// Mutate the exposed per-category collections through
        /// <see cref="AlgorithmSelection.ConfigureHazmat"/> before Start() to
        /// plug in extra algorithms (e.g. legacy ciphers or alternative
        /// names) per server, without forking the library. Mutations are
        /// reflected in the KEXINIT name-lists and in negotiation.
        /// </summary>
        public AlgorithmSelection Algorithms { get; } = new();

        /// <summary>
        /// Occurs when a client connection has been accepted and a
        /// <see cref="Session"/> created for it, before the SSH handshake
        /// starts. Handlers can configure the session or subscribe to its
        /// events.
        /// </summary>
        public event EventHandler<Session> ConnectionAccepted;

        /// <summary>
        /// Occurs when a session's protocol loop terminates with an
        /// exception. This includes normal connection loss
        /// (<see cref="DisconnectReason.ConnectionLost"/>, e.g. the client
        /// closed the TCP connection), not only protocol errors.
        /// </summary>
        public event EventHandler<Exception> ExceptionRaised;

        /// <summary>
        /// Starts the server and blocks until the listener is running.
        /// </summary>
        /// <exception cref="InvalidOperationException">The server is already started.</exception>
        /// <exception cref="ObjectDisposedException">The server has been disposed.</exception>
        public void Start() => StartAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Stops the server: closes the listener and disconnects every active
        /// session. Blocks until the shutdown completes. A server that is not
        /// running is left unchanged.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The server has been disposed.</exception>
        public void Stop() => StopAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Starts the server: freezes the algorithm selection built from
        /// <see cref="Algorithms"/>, binds a TCP listener to the address and
        /// port in <see cref="StartingInfo"/>, and begins accepting
        /// connections asynchronously, each handled by a new
        /// <see cref="Session"/>.
        /// </summary>
        /// <param name="cancellationToken">
        /// A token that cancels the accept loop and the sessions it started.
        /// </param>
        /// <returns>A task that completes once the listener is running.</returns>
        /// <exception cref="InvalidOperationException">The server is already started.</exception>
        /// <exception cref="ObjectDisposedException">The server has been disposed.</exception>
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
                var hostKey = catalog.HostKeyCollection.NegotiableNames.Intersect(_hostKey.Keys);
                var kex = catalog.KeyExchangeCollection.NegotiableNames;
                var cipher = catalog.EncryptionCollection.NegotiableNames;
                var hmac = catalog.HmacCollection.NegotiableNames;
                var compression = catalog.CompressionCollection.NegotiableNames;

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

        /// <summary>
        /// Stops accepting connections and asynchronously disconnects every
        /// active session. Does nothing if the server is not currently
        /// running.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The server has been disposed.</exception>
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

        /// <summary>
        /// Registers a host key for a public key algorithm. Only the first key
        /// registered under a given algorithm name is used; later calls with
        /// the same name are ignored.
        /// </summary>
        /// <param name="type">
        /// The host key algorithm name (e.g. "rsa-sha2-512",
        /// "ecdsa-sha2-nistp256").
        /// </param>
        /// <param name="xml">The PEM-encoded private key for the algorithm.</param>
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
        /// <summary>
        /// Stops the server asynchronously (see <see cref="StopAsync"/>) and
        /// marks it disposed. Subsequent calls have no effect; afterwards
        /// <see cref="StartAsync(CancellationToken)"/> and
        /// <see cref="StopAsync"/> throw
        /// <see cref="ObjectDisposedException"/>.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (Volatile.Read(ref _isDisposed) == 1)
                return;
            await StopAsync();
            if (Interlocked.CompareExchange(ref _isDisposed, 1, 0) == 0)
                GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Stops the server synchronously (see <see cref="Stop"/>) and marks
        /// it disposed. Subsequent calls have no effect; afterwards
        /// <see cref="Start"/> and <see cref="Stop"/> throw
        /// <see cref="ObjectDisposedException"/>.
        /// </summary>
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
