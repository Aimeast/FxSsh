using System;
using FxSsh.Messages;
using FxSsh.Messages.Connection;
using FxSsh.Messages.UserAuth;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Messages
{
    [TestClass]
    public sealed class MessageRegistryTests
    {
        // Mirrors MessageRegistry's factory table: every inbound
        // (client -> server) message number must resolve to its type.
        private static readonly (byte Number, Type Expected)[] RegisteredTypes =
        {
            (DisconnectMessage.MessageNumber, typeof(DisconnectMessage)),
            (ShouldIgnoreMessage.MessageNumber, typeof(ShouldIgnoreMessage)),
            (UnimplementedMessage.MessageNumber, typeof(UnimplementedMessage)),
            (ServiceRequestMessage.MessageNumber, typeof(ServiceRequestMessage)),
            (ExtInfoMessage.MessageNumber, typeof(ExtInfoMessage)),
            (KeyExchangeInitMessage.MessageNumber, typeof(KeyExchangeInitMessage)),
            (NewKeysMessage.MessageNumber, typeof(NewKeysMessage)),
            (KeyExchangeXInitMessage.MessageNumber, typeof(KeyExchangeXInitMessage)),
            (RequestMessage.MessageNumber, typeof(RequestMessage)),
            (GlobalRequestMessage.MessageNumber, typeof(GlobalRequestMessage)),
            (RequestSuccessMessage.MessageNumber, typeof(RequestSuccessMessage)),
            (RequestFailureMessage.MessageNumber, typeof(RequestFailureMessage)),
            (ChannelOpenMessage.MessageNumber, typeof(ChannelOpenMessage)),
            (ChannelOpenConfirmationMessage.MessageNumber, typeof(ChannelOpenConfirmationMessage)),
            (ChannelOpenFailureMessage.MessageNumber, typeof(ChannelOpenFailureMessage)),
            (ChannelWindowAdjustMessage.MessageNumber, typeof(ChannelWindowAdjustMessage)),
            (ChannelDataMessage.MessageNumber, typeof(ChannelDataMessage)),
            (ChannelEofMessage.MessageNumber, typeof(ChannelEofMessage)),
            (ChannelCloseMessage.MessageNumber, typeof(ChannelCloseMessage)),
            (ChannelRequestMessage.MessageNumber, typeof(ChannelRequestMessage)),
        };

        [TestMethod]
        public void TryCreate_resolves_every_registered_inbound_message()
        {
            foreach (var (number, expected) in RegisteredTypes)
            {
                var found = MessageRegistry.TryCreate(number, out var message);

                Assert.IsTrue(found, $"message number {number} should be registered");
                Assert.IsInstanceOfType(message, expected);
                Assert.AreEqual(number, message!.MessageType, $"message number {number}");
            }
        }

        [TestMethod]
        public void TryCreate_returns_false_for_unregistered_or_outbound_numbers()
        {
            // 4 = SSH_MSG_DEBUG (not implemented), 6/51/52/60/10/11 are
            // server -> client messages a server never receives, 95 is
            // unassigned, 99/100 are channel replies.
            byte[] unregistered = { 4, 6, 10, 11, 51, 52, 60, 95, 99, 100 };

            foreach (var number in unregistered)
            {
                var found = MessageRegistry.TryCreate(number, out var message);

                Assert.IsFalse(found, $"message number {number} should not be registered");
                Assert.IsNull(message);
            }
        }

        [TestMethod]
        public void Outbound_only_message_types_are_not_registered()
        {
            // ServiceAccept / Userauth Success & Failure / PublicKeyOk are
            // produced by the server; their numbers must fall through so the
            // session replies with SSH_MSG_UNIMPLEMENTED instead of parsing.
            Assert.IsFalse(MessageRegistry.TryCreate(ServiceAcceptMessage.MessageNumber, out _));
            Assert.IsFalse(MessageRegistry.TryCreate(FailureMessage.MessageNumber, out _));
            Assert.IsFalse(MessageRegistry.TryCreate(SuccessMessage.MessageNumber, out _));
            Assert.IsFalse(MessageRegistry.TryCreate(PublicKeyOkMessage.MessageNumber, out _));
        }
    }
}
