using System;
using System.Text;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Messages.UserAuth;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Messages
{
    /// <summary>
    /// Server-side parse paths: hand-built wire payloads (what a client
    /// sends) are loaded, plus the error paths for malformed or mismatched
    /// payloads.
    /// </summary>
    [TestClass]
    public sealed class MessageParseTests
    {
        [TestMethod]
        public void ServiceRequestMessage_loads_service_name()
        {
            var message = new ServiceRequestMessage();
            message.Load(TestMessages.Payload(ServiceRequestMessage.MessageNumber)
                .Write("ssh-userauth", Encoding.ASCII)
                .ToByteArray());

            Assert.AreEqual("ssh-userauth", message.ServiceName);
        }

        [TestMethod]
        public void KeyExchangeXInitMessage_loads_leaving_payload_unparsed()
        {
            var message = new KeyExchangeXInitMessage();
            message.Load(TestMessages.Payload(KeyExchangeXInitMessage.MessageNumber)
                .Write("unparsed", Encoding.ASCII)
                .ToByteArray());
        }

        [TestMethod]
        public void DhInit_and_ECDhInit_are_reparsed_with_protocol_context()
        {
            var e = new byte[] { 0x12, 0x34 };
            var dhPacket = TestMessages.Payload(KeyExchangeXInitMessage.MessageNumber)
                .WriteMpint(e)
                .ToByteArray();
            var dhBase = new KeyExchangeXInitMessage();
            dhBase.Load(dhPacket);
            var dhInit = Message.LoadFrom<KeyExchangeDhInitMessage>(dhBase);

            CollectionAssert.AreEqual(e, dhInit.E);

            var q = new byte[] { 0x04, 0xAA, 0xBB };
            var ecPacket = TestMessages.Payload(KeyExchangeXInitMessage.MessageNumber)
                .WriteBinary(q)
                .ToByteArray();
            var ecBase = new KeyExchangeXInitMessage();
            ecBase.Load(ecPacket);
            var ecdhInit = Message.LoadFrom<KeyExchangeECDhInitMessage>(ecBase);

            CollectionAssert.AreEqual(q, ecdhInit.Q);
        }

        [TestMethod]
        public void ChannelOpenMessage_loads_channel_fields()
        {
            var message = new ChannelOpenMessage();
            message.Load(TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write("session", Encoding.ASCII)
                .Write(3u)
                .Write(0x200000u)
                .Write(32768u)
                .ToByteArray());

            Assert.AreEqual("session", message.ChannelType);
            Assert.AreEqual(3u, message.SenderChannel);
            Assert.AreEqual(0x200000u, message.InitialWindowSize);
            Assert.AreEqual(32768u, message.MaximumPacketSize);
        }

        [TestMethod]
        public void SessionOpenMessage_accepts_session_channel_type()
        {
            var session = ParseChannelOpen<SessionOpenMessage>("session");

            Assert.AreEqual("session", session.ChannelType);
        }

        [TestMethod]
        public void SessionOpenMessage_rejects_non_session_channel_type()
        {
            Assert.ThrowsExactly<ArgumentException>(() => ParseChannelOpen<SessionOpenMessage>("x11"));
        }

        [TestMethod]
        public void DirectTcpIpMessage_loads_forwarding_fields()
        {
            var packet = ChannelOpenPacket("direct-tcpip", writer => writer
                .Write("internal.example", Encoding.ASCII)
                .Write(8080u)
                .Write("127.0.0.1", Encoding.ASCII)
                .Write(54321u));
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(packet);

            var direct = Message.LoadFrom<DirectTcpIpMessage>(baseMessage);

            Assert.AreEqual("internal.example", direct.Host);
            Assert.AreEqual(8080u, direct.Port);
            Assert.AreEqual("127.0.0.1", direct.OriginatorIPAddress);
            Assert.AreEqual(54321u, direct.OriginatorPort);
        }

        [TestMethod]
        public void DirectTcpIpMessage_rejects_other_channel_types()
        {
            Assert.ThrowsExactly<ArgumentException>(() => ParseChannelOpen<DirectTcpIpMessage>("session"));
        }

        [TestMethod]
        public void ForwardedTcpIpMessage_loads_forwarding_fields()
        {
            var packet = ChannelOpenPacket("forwarded-tcpip", writer => writer
                .Write("127.0.0.1", Encoding.ASCII)
                .Write(4444u)
                .Write("10.0.0.1", Encoding.ASCII)
                .Write(5555u));
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(packet);

            var forwarded = Message.LoadFrom<ForwardedTcpIpMessage>(baseMessage);

            Assert.AreEqual("127.0.0.1", forwarded.Address);
            Assert.AreEqual(4444u, forwarded.Port);
            Assert.AreEqual("10.0.0.1", forwarded.OriginatorIPAddress);
            Assert.AreEqual(5555u, forwarded.OriginatorPort);
        }

        private static byte[] ChannelOpenPacket(string channelType, Action<SshDataWriter> writeRest)
        {
            var writer = TestMessages.Payload(ChannelOpenMessage.MessageNumber)
                .Write(channelType, Encoding.ASCII)
                .Write(1u)
                .Write(0x200000u)
                .Write(32768u);
            writeRest(writer);
            return writer.ToByteArray();
        }

        private static T ParseChannelOpen<T>(string channelType) where T : ChannelOpenMessage, new()
        {
            var baseMessage = new ChannelOpenMessage();
            baseMessage.Load(ChannelOpenPacket(channelType, _ => { }));
            return Message.LoadFrom<T>(baseMessage);
        }

        private static byte[] ChannelRequestPacket(string requestType, bool wantReply, Action<SshDataWriter>? writeRest)
        {
            var writer = TestMessages.Payload(ChannelRequestMessage.MessageNumber)
                .Write(6u)
                .Write(requestType, Encoding.ASCII)
                .Write(wantReply);
            writeRest?.Invoke(writer);
            return writer.ToByteArray();
        }

        private static T ParseChannelRequest<T>(string requestType, bool wantReply, Action<SshDataWriter>? writeRest)
            where T : ChannelRequestMessage, new()
        {
            var baseMessage = new ChannelRequestMessage();
            baseMessage.Load(ChannelRequestPacket(requestType, wantReply, writeRest));
            return Message.LoadFrom<T>(baseMessage);
        }

        [TestMethod]
        public void PtyRequestMessage_loads_terminal_fields()
        {
            var pty = ParseChannelRequest<PtyRequestMessage>("pty-req", true, writer => writer
                .Write("xterm-256color", Encoding.ASCII)
                .Write(120u)
                .Write(40u)
                .Write(960u)
                .Write(640u)
                .WriteBinary(new byte[] { 0x80, 0x00 }));

            Assert.AreEqual(6u, pty.RecipientChannel);
            Assert.AreEqual("pty-req", pty.RequestType);
            Assert.IsTrue(pty.WantReply);
            Assert.AreEqual("xterm-256color", pty.Terminal);
            Assert.AreEqual(120u, pty.widthChars);
            Assert.AreEqual(40u, pty.heightRows);
            Assert.AreEqual(960u, pty.widthPx);
            Assert.AreEqual(640u, pty.heightPx);
            CollectionAssert.AreEqual(new byte[] { 0x80, 0x00 }, pty.modes);
        }

        [TestMethod]
        public void CommandRequestMessage_loads_command()
        {
            var exec = ParseChannelRequest<CommandRequestMessage>("exec", false, writer => writer
                .Write("ls -la", Encoding.ASCII));

            Assert.AreEqual("exec", exec.RequestType);
            Assert.IsFalse(exec.WantReply);
            Assert.AreEqual("ls -la", exec.Command);
        }

        [TestMethod]
        public void EnvMessage_loads_name_and_value()
        {
            var env = ParseChannelRequest<EnvMessage>("env", false, writer => writer
                .Write("LANG", Encoding.ASCII)
                .Write("zh_CN.UTF-8", Encoding.ASCII));

            Assert.AreEqual("LANG", env.Name);
            Assert.AreEqual("zh_CN.UTF-8", env.Value);
        }

        [TestMethod]
        public void ShellRequestMessage_loads_without_payload()
        {
            var shell = ParseChannelRequest<ShellRequestMessage>("shell", true, null);

            Assert.AreEqual("shell", shell.RequestType);
            Assert.IsTrue(shell.WantReply);
        }

        [TestMethod]
        public void SubsystemRequestMessage_loads_subsystem_name()
        {
            var sftp = ParseChannelRequest<SubsystemRequestMessage>("subsystem", false, writer => writer
                .Write("sftp", Encoding.ASCII));

            Assert.AreEqual("sftp", sftp.Name);
        }

        [TestMethod]
        public void WindowChangeMessage_loads_dimensions()
        {
            var resize = ParseChannelRequest<WindowChangeMessage>("window-change", false, writer => writer
                .Write(200u)
                .Write(50u)
                .Write(1600u)
                .Write(800u));

            Assert.AreEqual(200u, resize.WidthColumns);
            Assert.AreEqual(50u, resize.HeightRows);
            Assert.AreEqual(1600u, resize.WidthPixels);
            Assert.AreEqual(800u, resize.HeightPixels);
        }

        [TestMethod]
        public void RequestMessage_loads_userauth_fields()
        {
            var request = new RequestMessage();
            request.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("password", Encoding.ASCII)
                .ToByteArray());

            Assert.AreEqual("alice", request.Username);
            Assert.AreEqual("ssh-connection", request.ServiceName);
            Assert.AreEqual("password", request.MethodName);
        }

        [TestMethod]
        public void NoneRequestMessage_accepts_only_none_method()
        {
            var baseMessage = new RequestMessage();
            baseMessage.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("none", Encoding.ASCII)
                .ToByteArray());

            var none = Message.LoadFrom<NoneRequestMessage>(baseMessage);

            Assert.AreEqual("none", none.MethodName);
        }

        [TestMethod]
        public void NoneRequestMessage_rejects_other_methods()
        {
            var baseMessage = new RequestMessage();
            baseMessage.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("password", Encoding.ASCII)
                .ToByteArray());

            Assert.ThrowsExactly<ArgumentException>(
                () => Message.LoadFrom<NoneRequestMessage>(baseMessage));
        }

        [TestMethod]
        public void PasswordRequestMessage_loads_password()
        {
            var baseMessage = new RequestMessage();
            baseMessage.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("password", Encoding.ASCII)
                .Write(false)
                .Write("s3cret", Encoding.ASCII)
                .ToByteArray());

            var password = Message.LoadFrom<PasswordRequestMessage>(baseMessage);

            Assert.AreEqual("s3cret", password.Password);
        }

        [TestMethod]
        public void PasswordRequestMessage_rejects_other_methods()
        {
            var baseMessage = new RequestMessage();
            baseMessage.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("publickey", Encoding.ASCII)
                .ToByteArray());

            Assert.ThrowsExactly<ArgumentException>(
                () => Message.LoadFrom<PasswordRequestMessage>(baseMessage));
        }

        [TestMethod]
        public void PublicKeyRequestMessage_without_signature_loads_key_fields()
        {
            var keyBlob = new byte[] { 0x00, 0x11, 0x22 };
            var baseMessage = new RequestMessage();
            baseMessage.Load(TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("publickey", Encoding.ASCII)
                .Write(false)
                .Write("ecdsa-sha2-nistp256", Encoding.ASCII)
                .WriteBinary(keyBlob)
                .ToByteArray());

            var publicKey = Message.LoadFrom<PublicKeyRequestMessage>(baseMessage);

            Assert.IsFalse(publicKey.HasSignature);
            Assert.AreEqual("ecdsa-sha2-nistp256", publicKey.KeyAlgorithmName);
            CollectionAssert.AreEqual(keyBlob, publicKey.PublicKey);
            Assert.IsTrue(publicKey.Signature.IsEmpty);
        }

        [TestMethod]
        public void PublicKeyRequestMessage_with_signature_splits_signed_payload()
        {
            var keyBlob = new byte[] { 0x00, 0x11, 0x22 };
            var signature = new byte[] { 0xAA, 0xBB, 0xCC };
            var packet = TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("publickey", Encoding.ASCII)
                .Write(true)
                .Write("ecdsa-sha2-nistp256", Encoding.ASCII)
                .WriteBinary(keyBlob)
                .WriteBinary(signature)
                .ToByteArray();
            var baseMessage = new RequestMessage();
            baseMessage.Load(packet);

            var publicKey = Message.LoadFrom<PublicKeyRequestMessage>(baseMessage);

            Assert.IsTrue(publicKey.HasSignature);
            CollectionAssert.AreEqual(signature, publicKey.Signature.ToArray());
            // PayloadWithoutSignature is session_id || everything up to the
            // signature blob: the exact bytes the peer signed.
            Assert.AreEqual(packet.Length - signature.Length - 4, publicKey.PayloadWithoutSignature.Length);
            var expectedPrefix = TestMessages.Payload(RequestMessage.MessageNumber)
                .Write("alice", Encoding.UTF8)
                .Write("ssh-connection", Encoding.ASCII)
                .Write("publickey", Encoding.ASCII)
                .Write(true)
                .Write("ecdsa-sha2-nistp256", Encoding.ASCII)
                .WriteBinary(keyBlob)
                .ToByteArray();
            CollectionAssert.AreEqual(expectedPrefix, publicKey.PayloadWithoutSignature.ToArray());
        }

        [TestMethod]
        public void PublicKeyOkMessage_encodes_algorithm_and_key()
        {
            var keyBlob = new byte[] { 0x00, 0x11, 0x22 };
            var packet = new PublicKeyOkMessage
            {
                KeyAlgorithmName = "rsa-sha2-256",
                PublicKey = keyBlob,
            }.GetPacket();

            var reader = new SshDataReader(packet);
            Assert.AreEqual(PublicKeyOkMessage.MessageNumber, reader.ReadByte());
            Assert.AreEqual("rsa-sha2-256", reader.ReadString(Encoding.ASCII));
            CollectionAssert.AreEqual(keyBlob, reader.ReadBinary());
            Assert.AreEqual(0L, reader.DataAvailable);
        }

        [TestMethod]
        public void Userauth_Success_and_Failure_are_empty_and_fixed_payloads()
        {
            CollectionAssert.AreEqual(new byte[] { SuccessMessage.MessageNumber }, new SuccessMessage().GetPacket());

            var failure = new FailureMessage().GetPacket();
            var reader = new SshDataReader(failure);
            Assert.AreEqual(FailureMessage.MessageNumber, reader.ReadByte());
            Assert.AreEqual("password,publickey", reader.ReadString(Encoding.ASCII));
            Assert.IsFalse(reader.ReadBoolean());
        }

        [TestMethod]
        public void Load_rejects_payload_with_wrong_leading_message_number()
        {
            var message = new DisconnectMessage();

            Assert.ThrowsExactly<ArgumentException>(
                () => message.Load(TestMessages.Payload(UnimplementedMessage.MessageNumber).Write(7u).ToByteArray()));
        }

        [TestMethod]
        public void DisconnectMessage_without_language_field_leaves_language_unset()
        {
            var message = new DisconnectMessage();
            message.Load(TestMessages.Payload(DisconnectMessage.MessageNumber)
                .Write((uint)DisconnectReason.TooManyConnections)
                .Write("busy", Encoding.UTF8)
                .ToByteArray());

            Assert.AreEqual(DisconnectReason.TooManyConnections, message.ReasonCode);
            Assert.AreEqual("busy", message.Description);
            Assert.IsNull(message.Language);
        }

        [TestMethod]
        public void Messages_without_load_support_throw_on_Load()
        {
            // ServiceAccept is server -> client only: the base class default
            // OnLoad throws rather than mis-parsing an inbound packet.
            Assert.ThrowsExactly<NotSupportedException>(
                () => new ServiceAcceptMessage("ssh-userauth").Load(new byte[] { ServiceAcceptMessage.MessageNumber }));
        }

        [TestMethod]
        public void Messages_without_encode_support_throw_on_GetPacket()
        {
            // RequestMessage is inbound only: the base class default
            // OnGetPacket throws rather than emitting a half-formed packet.
            Assert.ThrowsExactly<NotSupportedException>(() => new RequestMessage().GetPacket());
        }

        [TestMethod]
        public void UnknownMessage_type_number_throws_and_can_make_unimplemented()
        {
            var unknown = new UnknownMessage { SequenceNumber = 77, UnknownMessageType = 200 };

            Assert.ThrowsExactly<NotSupportedException>(() => _ = unknown.MessageType);

            var unimplemented = unknown.MakeUnimplementedMessage();
            Assert.AreEqual(77u, unimplemented.SequenceNumber);
        }

        [TestMethod]
        public void LoadFrom_rejects_null()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => Message.LoadFrom<DisconnectMessage>(null!));
        }
    }
}
