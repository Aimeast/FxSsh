using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SshNet
{
    public class SshServer : IDisposable
    {
        private readonly object _lock = new object();
        private readonly List<Session> _sessions = new List<Session>();
        private bool _isDisposed;
        private bool _started;
        private TcpListener _listenser = null;
        private string _hostKey = null;

        public SshServer()
            : this(new StartingInfo())
        { }

        public SshServer(StartingInfo info)
        {
            Contract.Requires(info != null);

            StartingInfo = info;
        }

        public StartingInfo StartingInfo { get; private set; }

        public void Start()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (_started)
                    throw new InvalidOperationException("The server is already started.");

                _listenser = StartingInfo.LocalAddress == IPAddress.IPv6Any
                    ? TcpListener.Create(StartingInfo.Port) // dual stack
                    : new TcpListener(StartingInfo.LocalAddress, StartingInfo.Port);
                _listenser.Start();
                Task.Run(() => AcceptSocket());

                _started = true;
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                CheckDisposed();
                if (!_started)
                    throw new InvalidOperationException("The server is not started.");

                _listenser.Stop();

                foreach (var session in _sessions)
                {
                    try
                    {
                        session.Disconnect();
                    }
                    catch
                    {
                    }
                }

                _isDisposed = true;
                _started = false;
            }
        }

        public void SetHostKey(string xml)
        {
            _hostKey = xml;
        }

        private void AcceptSocket()
        {
            while (true)
            {
                try
                {
                    var socket = _listenser.AcceptSocket();
                    var session = new Session(socket, _hostKey);
                    session.Disconnected += (ss, ee) => _sessions.Remove(session);
                    _sessions.Add(session);
                    Task.Run(() =>
                    {
                        try
                        {
                            session.EstablishConnection();
                        }
                        catch
                        {
                            session.Disconnect();
                        }
                    });
                }
                catch (InvalidOperationException)
                {
                    if (_isDisposed || !_started)
                        return;

                    throw;
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().FullName);
        }

        #region IDisposable
        public void Dispose()
        {
            lock (_lock)
            {
                if (_isDisposed)
                    return;
                Stop();
            }
        }
        #endregion
    }
}
