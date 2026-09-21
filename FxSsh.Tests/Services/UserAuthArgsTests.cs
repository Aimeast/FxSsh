using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using FxSsh;
using FxSsh.Services;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services
{
    [TestClass]
    public sealed class UserAuthArgsTests
    {
        [TestMethod]
        public void None_ctor_defaults()
        {
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var session = new Session(socket, new Dictionary<string, string>(), "SSH-2.0-X");

            var args = new UserAuthArgs(session);

            Assert.AreEqual("none", args.AuthMethod);
            Assert.IsNull(args.Username);
            Assert.IsNull(args.Password);
            Assert.IsNull(args.KeyAlgorithm);
            Assert.IsNull(args.Fingerprint);
            Assert.IsNull(args.Key);
            Assert.IsFalse(args.Result);
            Assert.AreSame(session, args.Session);

            session.Disconnect();
            socket.Dispose();
        }

        [TestMethod]
        public void Password_ctor_carries_credentials()
        {
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var session = new Session(socket, new Dictionary<string, string>(), "SSH-2.0-X");

            var args = new UserAuthArgs(session, "alice", "secret");

            Assert.AreEqual("password", args.AuthMethod);
            Assert.AreEqual("alice", args.Username);
            Assert.AreEqual("secret", args.Password);
            Assert.AreSame(session, args.Session);

            session.Disconnect();
            socket.Dispose();
        }

        [TestMethod]
        public void PublicKey_ctor_carries_key_material()
        {
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var session = new Session(socket, new Dictionary<string, string>(), "SSH-2.0-X");
            var key = new byte[] { 0x00, 0x11 };

            var args = new UserAuthArgs(session, "bob", "rsa-sha2-512", "fingerprint", key);

            Assert.AreEqual("publickey", args.AuthMethod);
            Assert.AreEqual("bob", args.Username);
            Assert.AreEqual("rsa-sha2-512", args.KeyAlgorithm);
            Assert.AreEqual("fingerprint", args.Fingerprint);
            CollectionAssert.AreEqual(key, args.Key);

            session.Disconnect();
            socket.Dispose();
        }

        [TestMethod]
        public void PublicKey_ctor_validates_arguments()
        {
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var session = new Session(socket, new Dictionary<string, string>(), "SSH-2.0-X");
            var key = new byte[] { 0x00 };

            Assert.ThrowsExactly<ArgumentNullException>(() => new UserAuthArgs(session, "bob", null!, "fp", key));
            Assert.ThrowsExactly<ArgumentNullException>(() => new UserAuthArgs(session, "bob", "alg", null!, key));
            Assert.ThrowsExactly<ArgumentNullException>(() => new UserAuthArgs(session, "bob", "alg", "fp", null!));

            session.Disconnect();
            socket.Dispose();
        }

        [TestMethod]
        public void Password_ctor_validates_arguments()
        {
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            var session = new Session(socket, new Dictionary<string, string>(), "SSH-2.0-X");

            Assert.ThrowsExactly<ArgumentNullException>(() => new UserAuthArgs(session, null!, "pw"));
            Assert.ThrowsExactly<ArgumentNullException>(() => new UserAuthArgs(session, "alice", null!));

            session.Disconnect();
            socket.Dispose();
        }
    }
}
