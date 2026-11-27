using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Services;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// Lifecycle behaviour of an engine attached to a real session channel.
    /// An abrupt channel teardown does not deliver CHANNEL_CLOSE, so the
    /// engine must still cancel its waiters and release its handles.
    /// </summary>
    [TestClass]
    public sealed class SftpAttachLifecycleTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;
        private ConnectionService _connection = null!;

        [TestInitialize]
        public void CreateSessionOverSocketPair()
        {
            using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            listener.Listen(1);

            _clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _clientSocket.Connect(listener.LocalEndPoint!);
            _serverSocket = listener.Accept();

            _session = new Session(_serverSocket, new Dictionary<string, string>(), "SSH-2.0-FxSsh-Test");
            _connection = new ConnectionService(_session, new UserAuthArgs(_session));
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _clientSocket.Dispose();
            _serverSocket.Dispose();
        }

        [TestMethod]
        public async Task ForceClose_cancels_WaitForClose_and_tears_the_engine_down()
        {
            using var service = new SftpService(new InMemorySftpFileSystem());
            var channel = new SessionChannel(_connection, 1, 1 << 20, 32768, 9);

            service.Attach(channel);

            var wait = Task.Run(service.WaitForClose);
            await Task.Delay(100);
            Assert.IsFalse(wait.IsCompleted, "WaitForClose must block until teardown");

            channel.ForceClose();

            await wait.WaitAsync(TimeSpan.FromSeconds(5));
            service.Dispose(); // idempotent after the forced close
        }

        [TestMethod]
        public void Attach_rejects_a_second_channel()
        {
            using var service = new SftpService(new InMemorySftpFileSystem());
            var first = new SessionChannel(_connection, 1, 1 << 20, 32768, 9);
            var second = new SessionChannel(_connection, 2, 1 << 20, 32768, 10);

            service.Attach(first);

            Assert.ThrowsExactly<InvalidOperationException>(() => service.Attach(second));

            first.ForceClose();
        }
    }
}
