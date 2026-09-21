using System;
using System.Text;
using FxSsh.Messages.Connection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Messages
{
    [TestClass]
    public sealed class ForwardedTcpIpOpenMessageTests
    {
        [TestMethod]
        public void Encodes_forwarded_tcpip_channel_open()
        {
            var message = new ForwardedTcpIpOpenMessage(
                senderChannel: 9,
                initialWindowSize: 0x200000,
                maximumPacketSize: 32768,
                connectedAddress: "127.0.0.1",
                connectedPort: 8443,
                originatorIPAddress: "10.0.0.7",
                originatorPort: 51000);

            var packet = message.GetPacket();

            var reader = new SshDataReader(packet);
            Assert.AreEqual(ChannelOpenMessage.MessageNumber, reader.ReadByte());
            Assert.AreEqual("forwarded-tcpip", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(9u, reader.ReadUInt32());
            Assert.AreEqual(0x200000u, reader.ReadUInt32());
            Assert.AreEqual(32768u, reader.ReadUInt32());
            Assert.AreEqual("127.0.0.1", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(8443u, reader.ReadUInt32());
            Assert.AreEqual("10.0.0.7", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(51000u, reader.ReadUInt32());
            Assert.AreEqual(0L, reader.DataAvailable);
        }

        [TestMethod]
        public void Null_addresses_are_encoded_as_empty_strings()
        {
            var message = new ForwardedTcpIpOpenMessage(1, 0, 0, null!, 0, null!, 0);

            var packet = message.GetPacket();

            var reader = new SshDataReader(packet);
            reader.ReadByte();
            Assert.AreEqual("forwarded-tcpip", reader.ReadString(Encoding.ASCII));
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();
            Assert.AreEqual(string.Empty, reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(0u, reader.ReadUInt32());
            Assert.AreEqual(string.Empty, reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(0u, reader.ReadUInt32());
        }
    }
}
