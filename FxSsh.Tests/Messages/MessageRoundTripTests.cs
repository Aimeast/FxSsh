using System;
using System.Text;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Messages
{
    /// <summary>
    /// Round-trips for messages that both encode (GetPacket) and decode
    /// (Load): serialize a populated message, parse it back, and assert the
    /// fields survive.
    /// </summary>
    [TestClass]
    public sealed class MessageRoundTripTests
    {
        private static T RoundTrip<T>(T message) where T : Message, new()
        {
            var parsed = new T();
            parsed.Load(message.GetPacket());
            return parsed;
        }

        [TestMethod]
        public void DisconnectMessage_round_trips()
        {
            var sent = new DisconnectMessage(DisconnectReason.ProtocolError, "goodbye", "zh");

            var received = RoundTrip(sent);

            Assert.AreEqual(DisconnectReason.ProtocolError, received.ReasonCode);
            Assert.AreEqual("goodbye", received.Description);
            Assert.AreEqual("zh", received.Language);
        }

        [TestMethod]
        public void DisconnectMessage_defaults_language_to_en()
        {
            var sent = new DisconnectMessage(DisconnectReason.ByApplication);

            var received = RoundTrip(sent);

            Assert.AreEqual(DisconnectReason.ByApplication, received.ReasonCode);
            Assert.AreEqual(string.Empty, received.Description);
            Assert.AreEqual("en", received.Language);
        }

        [TestMethod]
        public void UnimplementedMessage_round_trips_sequence_number()
        {
            var sent = new UnimplementedMessage { SequenceNumber = 42 };

            var received = RoundTrip(sent);

            Assert.AreEqual(42u, received.SequenceNumber);
        }

        [TestMethod]
        public void ExtInfoMessage_round_trips_and_orders_extensions()
        {
            var sent = new ExtInfoMessage();
            sent.Extensions["zebra"] = "z";
            sent.Extensions["apple"] = "a";

            var packet = sent.GetPacket();
            var received = new ExtInfoMessage();
            received.Load(packet);

            Assert.AreEqual(2, received.Extensions.Count);
            Assert.AreEqual("a", received.Extensions["apple"]);
            Assert.AreEqual("z", received.Extensions["zebra"]);

            // RFC 8308 2.2: extensions MUST be sorted ascending by name.
            var reader = new SshDataReader(packet);
            reader.ReadByte();
            Assert.AreEqual(2u, reader.ReadUInt32());
            Assert.AreEqual("apple", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual("a", reader.ReadString(Encoding.UTF8));
            Assert.AreEqual("zebra", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual("z", reader.ReadString(Encoding.UTF8));
        }

        [TestMethod]
        public void KeyExchangeInitMessage_round_trips_all_name_lists()
        {
            var sent = new KeyExchangeInitMessage
            {
                KeyExchangeAlgorithms = new[] { "curve25519-sha256", "ext-info-s" },
                ServerHostKeyAlgorithms = new[] { "rsa-sha2-512" },
                EncryptionAlgorithmsClientToServer = new[] { "aes256-ctr" },
                EncryptionAlgorithmsServerToClient = new[] { "aes256-gcm@openssh.com" },
                MacAlgorithmsClientToServer = new[] { "hmac-sha2-256-etm@openssh.com" },
                MacAlgorithmsServerToClient = new[] { "hmac-sha2-512-etm@openssh.com" },
                CompressionAlgorithmsClientToServer = new[] { "none" },
                CompressionAlgorithmsServerToClient = new[] { "none" },
                LanguagesClientToServer = new[] { "en" },
                LanguagesServerToClient = new[] { "zh" },
                FirstKexPacketFollows = true,
                Reserved = 0,
            };
            var cookie = sent.Cookie;

            var received = RoundTrip(sent);

            CollectionAssert.AreEqual(cookie, received.Cookie);
            CollectionAssert.AreEqual(sent.KeyExchangeAlgorithms, received.KeyExchangeAlgorithms);
            CollectionAssert.AreEqual(sent.ServerHostKeyAlgorithms, received.ServerHostKeyAlgorithms);
            CollectionAssert.AreEqual(sent.EncryptionAlgorithmsClientToServer, received.EncryptionAlgorithmsClientToServer);
            CollectionAssert.AreEqual(sent.EncryptionAlgorithmsServerToClient, received.EncryptionAlgorithmsServerToClient);
            CollectionAssert.AreEqual(sent.MacAlgorithmsClientToServer, received.MacAlgorithmsClientToServer);
            CollectionAssert.AreEqual(sent.MacAlgorithmsServerToClient, received.MacAlgorithmsServerToClient);
            CollectionAssert.AreEqual(sent.CompressionAlgorithmsClientToServer, received.CompressionAlgorithmsClientToServer);
            CollectionAssert.AreEqual(sent.CompressionAlgorithmsServerToClient, received.CompressionAlgorithmsServerToClient);
            CollectionAssert.AreEqual(sent.LanguagesClientToServer, received.LanguagesClientToServer);
            CollectionAssert.AreEqual(sent.LanguagesServerToClient, received.LanguagesServerToClient);
            Assert.IsTrue(received.FirstKexPacketFollows);
            Assert.AreEqual(0u, received.Reserved);
        }

        [TestMethod]
        public void KeyExchangeInitMessage_collects_ext_info_markers_from_kex_list()
        {
            var received = new KeyExchangeInitMessage();
            received.Load(TestMessages.Payload(KeyExchangeInitMessage.MessageNumber)
                .WriteBytes(new byte[16])
                .Write("curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write("", Encoding.ASCII)
                .Write(false)
                .Write(0u)
                .ToByteArray());

            Assert.AreEqual(1, received.PeerExtensions.Count);
            Assert.IsTrue(received.PeerExtensions.Contains("ext-info-c"));
            Assert.IsFalse(received.PeerExtensions.Contains("kex-strict-c-v00@openssh.com"));
        }

        [TestMethod]
        public void NewKeysMessage_packet_is_a_single_message_number_byte()
        {
            CollectionAssert.AreEqual(new byte[] { NewKeysMessage.MessageNumber }, new NewKeysMessage().GetPacket());

            var received = new NewKeysMessage();
            received.Load(new byte[] { NewKeysMessage.MessageNumber });
        }

        [TestMethod]
        public void ChannelOpenConfirmationMessage_round_trips()
        {
            var sent = new ChannelOpenConfirmationMessage
            {
                RecipientChannel = 1,
                SenderChannel = 2,
                InitialWindowSize = 0x100000,
                MaximumPacketSize = 32768,
            };

            var received = RoundTrip(sent);

            Assert.AreEqual(1u, received.RecipientChannel);
            Assert.AreEqual(2u, received.SenderChannel);
            Assert.AreEqual(0x100000u, received.InitialWindowSize);
            Assert.AreEqual(32768u, received.MaximumPacketSize);
        }

        [TestMethod]
        public void ChannelOpenFailureMessage_round_trips()
        {
            var sent = new ChannelOpenFailureMessage
            {
                RecipientChannel = 3,
                ReasonCode = ChannelOpenFailureReason.ConnectFailed,
                Description = "no route",
                Language = "en",
            };

            var received = RoundTrip(sent);

            Assert.AreEqual(3u, received.RecipientChannel);
            Assert.AreEqual(ChannelOpenFailureReason.ConnectFailed, received.ReasonCode);
            Assert.AreEqual("no route", received.Description);
            Assert.AreEqual("en", received.Language);
        }

        [TestMethod]
        public void ChannelWindowAdjustMessage_round_trips()
        {
            var sent = new ChannelWindowAdjustMessage { RecipientChannel = 5, BytesToAdd = 0xDEAD };

            var received = RoundTrip(sent);

            Assert.AreEqual(5u, received.RecipientChannel);
            Assert.AreEqual(0xDEADu, received.BytesToAdd);
        }

        [TestMethod]
        public void ChannelDataMessage_round_trips_binary_payload()
        {
            var payload = new byte[] { 0x00, 0x01, 0xFF, 0x80 };
            var sent = new ChannelDataMessage { RecipientChannel = 7, Data = payload };

            var received = RoundTrip(sent);

            Assert.AreEqual(7u, received.RecipientChannel);
            CollectionAssert.AreEqual(payload, received.Data.ToArray());
        }

        [TestMethod]
        public void ChannelDataMessage_allows_empty_payload()
        {
            var sent = new ChannelDataMessage { RecipientChannel = 7, Data = ReadOnlyMemory<byte>.Empty };

            var received = RoundTrip(sent);

            Assert.AreEqual(7u, received.RecipientChannel);
            Assert.AreEqual(0, received.Data.Length);
        }

        [TestMethod]
        public void ChannelEof_and_ChannelClose_round_trip_recipient_channel()
        {
            Assert.AreEqual(9u, RoundTrip(new ChannelEofMessage { RecipientChannel = 9 }).RecipientChannel);
            Assert.AreEqual(10u, RoundTrip(new ChannelCloseMessage { RecipientChannel = 10 }).RecipientChannel);
        }

        [TestMethod]
        public void ChannelRequestMessage_round_trips()
        {
            var sent = new ChannelRequestMessage
            {
                RecipientChannel = 4,
                RequestType = "pty-req",
                WantReply = true,
            };

            var received = RoundTrip(sent);

            Assert.AreEqual(4u, received.RecipientChannel);
            Assert.AreEqual("pty-req", received.RequestType);
            Assert.IsTrue(received.WantReply);
        }

        [TestMethod]
        public void ChannelSuccess_and_ChannelFailure_encode_recipient_channel()
        {
            // Server -> client messages: encode only, so verify the bytes
            // directly instead of a message Load() round trip.
            var successPacket = new ChannelSuccessMessage { RecipientChannel = 11 }.GetPacket();
            var successReader = new SshDataReader(successPacket);
            Assert.AreEqual(ChannelSuccessMessage.MessageNumber, successReader.ReadByte());
            Assert.AreEqual(11u, successReader.ReadUInt32());

            var failurePacket = new ChannelFailureMessage { RecipientChannel = 12 }.GetPacket();
            var failureReader = new SshDataReader(failurePacket);
            Assert.AreEqual(ChannelFailureMessage.MessageNumber, failureReader.ReadByte());
            Assert.AreEqual(12u, failureReader.ReadUInt32());
        }

        [TestMethod]
        public void GlobalRequestMessage_round_trips_with_request_data()
        {
            var sent = new GlobalRequestMessage
            {
                RequestName = "tcpip-forward",
                WantReply = true,
                RequestData = new byte[] { 0x01, 0x02 },
            };

            var received = RoundTrip(sent);

            Assert.AreEqual("tcpip-forward", received.RequestName);
            Assert.IsTrue(received.WantReply);
            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02 }, received.RequestData);
        }

        [TestMethod]
        public void GlobalRequestMessage_without_data_round_trips()
        {
            var sent = new GlobalRequestMessage { RequestName = "keepalive@openssh.com", WantReply = false };

            var received = RoundTrip(sent);

            Assert.AreEqual("keepalive@openssh.com", received.RequestName);
            Assert.IsFalse(received.WantReply);
            Assert.AreEqual(0, received.RequestData.Length);
        }

        [TestMethod]
        public void RequestSuccess_and_RequestFailure_are_empty_payloads()
        {
            CollectionAssert.AreEqual(new byte[] { RequestSuccessMessage.MessageNumber }, new RequestSuccessMessage().GetPacket());
            CollectionAssert.AreEqual(new byte[] { RequestFailureMessage.MessageNumber }, new RequestFailureMessage().GetPacket());

            new RequestSuccessMessage().Load(new byte[] { RequestSuccessMessage.MessageNumber });
            new RequestFailureMessage().Load(new byte[] { RequestFailureMessage.MessageNumber });
        }

        [TestMethod]
        public void ExitStatusMessage_encodes_request_type_and_status()
        {
            var sent = new ExitStatusMessage { ExitStatus = 42 };

            var packet = sent.GetPacket();
            var request = new ChannelRequestMessage();
            request.Load(packet);

            Assert.AreEqual("exit-status", request.RequestType);
            Assert.IsFalse(request.WantReply);

            var reader = new SshDataReader(packet);
            reader.ReadByte();
            reader.ReadUInt32();
            reader.ReadString(Encoding.ASCII);
            reader.ReadBoolean();
            Assert.AreEqual(42u, reader.ReadUInt32());
            Assert.AreEqual(0L, reader.DataAvailable);
        }

        [TestMethod]
        public void ExitSignalMessage_encodes_signal_fields()
        {
            var sent = new ExitSignalMessage
            {
                SignalName = "TERM",
                CoreDumped = false,
                ErrorMessage = "killed",
                Language = "en",
            };

            var packet = sent.GetPacket();
            var request = new ChannelRequestMessage();
            request.Load(packet);

            Assert.AreEqual("exit-signal", request.RequestType);
            Assert.IsFalse(request.WantReply);

            var reader = new SshDataReader(packet);
            reader.ReadByte();
            reader.ReadUInt32();
            reader.ReadString(Encoding.ASCII);
            reader.ReadBoolean();
            Assert.AreEqual("TERM", reader.ReadString(Encoding.ASCII));
            Assert.IsFalse(reader.ReadBoolean());
            Assert.AreEqual("killed", reader.ReadString(Encoding.UTF8));
            Assert.AreEqual("en", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(0L, reader.DataAvailable);
        }

        [TestMethod]
        public void WritePayload_matches_GetPacket_bytes()
        {
            var sent = new DisconnectMessage(DisconnectReason.HostKeyNotVerifiable, "x", "en");
            var writer = new SshDataWriter();

            sent.WritePayload(writer);

            CollectionAssert.AreEqual(sent.GetPacket(), writer.ToByteArray());
        }
    }
}
