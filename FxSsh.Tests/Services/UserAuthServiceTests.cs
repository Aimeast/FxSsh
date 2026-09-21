using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Algorithms;
using FxSsh.Messages;
using FxSsh.Messages.UserAuth;
using FxSsh.Services;
using FxSsh.Tests.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    /// <summary>
    /// Drives UserAuthService's auth dispatch (friend assembly) with parsed
    /// SSH_MSG_USERAUTH_REQUEST payloads and observes accept/reject via the
    /// ServiceRegistered event (fired only on success).
    /// </summary>
    [TestClass]
    public sealed class UserAuthServiceTests
    {
        private Socket _clientSocket = null!;
        private Socket _serverSocket = null!;
        private Session _session = null!;

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
        }

        [TestCleanup]
        public void DisposeSockets()
        {
            _clientSocket.Dispose();
            _serverSocket.Dispose();
        }

        private static RequestMessage LoadRequest(params Action<SshDataWriter>[] fields)
        {
            var writer = TestMessages.Payload(RequestMessage.MessageNumber)
                .Write(UserAuthServiceTests.Username, Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII);
            foreach (var field in fields)
                field(writer);
            var request = new RequestMessage();
            request.Load(writer.ToByteArray());
            return request;
        }

        private static RequestMessage NoneRequest() => LoadRequest(w => w.Write("none", Encoding.ASCII));

        private static RequestMessage PasswordRequest(string password) =>
            LoadRequest(
                w => w.Write("password", Encoding.ASCII),
                w => w.Write(false),
                w => w.Write(password, Encoding.ASCII));

        private static RequestMessage PublicKeyRequest(string algorithm, byte[] keyBlob, bool hasSignature, byte[]? signature)
        {
            return LoadRequest(
                w => w.Write("publickey", Encoding.ASCII),
                w => w.Write(hasSignature),
                w => w.Write(algorithm, Encoding.ASCII),
                w => w.WriteBinary(keyBlob),
                w => { if (signature != null) w.WriteBinary(signature); });
        }

        private const string Username = "unit-tester";

        [TestMethod]
        public async Task None_auth_registers_the_connection_service_when_approved()
        {
            var service = new UserAuthService(_session);
            service.EnableNoneAuth = true;

            // The none-flow UserAuthArgs carries no username; approval is
            // purely the host's policy decision.
            service.UserAuth += (_, e) => e.Result = true;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            var svc = await registered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType(svc, typeof(ConnectionService));
        }

        [TestMethod]
        public async Task None_auth_is_rejected_when_the_handler_declines()
        {
            var service = new UserAuthService(_session);
            service.EnableNoneAuth = true;
            service.UserAuth += (_, e) => e.Result = false;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task None_auth_is_rejected_when_not_enabled()
        {
            var service = new UserAuthService(_session);
            Assert.IsFalse(service.EnableNoneAuth);

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(NoneRequest());

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task Password_auth_registers_on_match_and_rejects_on_mismatch()
        {
            var service = new UserAuthService(_session);
            var attempts = new List<UserAuthArgs>();
            service.UserAuth += (_, e) =>
            {
                attempts.Add(e);
                e.Result = e.Password == "right-password";
            };

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PasswordRequest("wrong-password"));
            await Task.Delay(300);
            Assert.AreEqual(1, attempts.Count);
            Assert.AreEqual("password", attempts[0].AuthMethod);
            Assert.AreEqual("wrong-password", attempts[0].Password);
            Assert.IsFalse(registered.Task.IsCompleted);

            service.HandleMessageCore(PasswordRequest("right-password"));
            var svc = await registered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsInstanceOfType(svc, typeof(ConnectionService));
        }

        [TestMethod]
        public async Task PublicKey_auth_reports_fingerprint_and_supports_policy_accept()
        {
            var service = new UserAuthService(_session);
            var attempts = new List<UserAuthArgs>();
            service.UserAuth += (_, e) =>
            {
                attempts.Add(e);
                e.Result = true;
            };

            var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
            var blob = new EcdsaKey("nistp256", pem).CreateKeyAndCertificatesData();

            // Two-phase: first request carries no signature; the server answers
            // PublicKeyOk (sent to the peer) without registering the service yet.
            service.HandleMessageCore(PublicKeyRequest("ecdsa-sha2-nistp256", blob, hasSignature: false, signature: null));

            await Task.Delay(300);
            Assert.AreEqual(1, attempts.Count);
            Assert.AreEqual("publickey", attempts[0].AuthMethod);
            Assert.AreEqual("ecdsa-sha2-nistp256", attempts[0].KeyAlgorithm);
            Assert.IsFalse(string.IsNullOrEmpty(attempts[0].Fingerprint));
            CollectionAssert.AreEqual(blob, attempts[0].Key);
        }

        [TestMethod]
        public async Task PublicKey_auth_with_invalid_signature_is_rejected()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) => e.Result = true;

            var pem = KeyGenerator.GenerateECDsaKeyPem("nistp256");
            var key = new EcdsaKey("nistp256", pem);
            var blob = key.CreateKeyAndCertificatesData();

            // Structurally valid SSH signature blob, but signed over different
            // data - the library must verify and reject without throwing.
            var wrongSignature = key.CreateSignatureData("other payload"u8.ToArray());

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PublicKeyRequest(
                "ecdsa-sha2-nistp256", blob, hasSignature: true, signature: wrongSignature));

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }

        [TestMethod]
        public async Task PublicKey_auth_with_unknown_algorithm_is_rejected()
        {
            var service = new UserAuthService(_session);
            service.UserAuth += (_, e) => e.Result = true;

            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(PublicKeyRequest(
                "ssh-dss", new byte[] { 0x00 }, hasSignature: false, signature: null));

            await Task.Delay(300);
            Assert.IsFalse(registered.Task.IsCompleted);
        }

        [TestMethod]
        public async Task Hostbased_method_is_rejected()
        {
            var service = new UserAuthService(_session);
            var registered = new TaskCompletionSource<SshService>();
            _session.ServiceRegistered += (_, s) => registered.TrySetResult(s);

            service.HandleMessageCore(LoadRequest(w => w.Write("hostbased", Encoding.ASCII)));

            await Assert.ThrowsExactlyAsync<TimeoutException>(
                () => registered.Task.WaitAsync(TimeSpan.FromMilliseconds(400)));
        }
    }
}
