using System;
using System.Collections.Generic;
using FxSsh.Messages.Connection;
using FxSsh.Messages.UserAuth;

namespace FxSsh.Messages;

/* This is the message registry, register supported messages here */
public class MessageRegistry {
    public static readonly Dictionary<int, Func<Message>> Registry = new() {
        {1, () => new DisconnectMessage()},
        {20, () => new KeyExchangeInitMessage()},
        {30, () => new KeyExchangeXInitMessage()},
        {31, () => new KeyExchangeXReplyMessage()},
        {21, () => new NewKeysMessage()},
        /*{6, () => new ServiceAcceptMessage()},*/
        {5, () => new ServiceRequestMessage()},
        {3, () => new UnimplementedMessage()},
        {51, () => new FailureMessage()},
        {60, () => new PublicKeyOkMessage()},
        {50, () => new RequestMessage()},
        {52, () => new SuccessMessage()},
        {97, () => new ChannelCloseMessage()},
        {94, () => new ChannelDataMessage()},
        {96, () => new ChannelEofMessage()},
        {100, () => new ChannelFailureMessage()},
        {91, () => new ChannelOpenConfirmationMessage()},
        {92, () => new ChannelOpenFailureMessage()},
        {90, () => new ChannelOpenMessage()},
        {98, () => new ChannelRequestMessage()},
        {99, () => new ChannelSuccessMessage()},
        {93, () => new ChannelWindowAdjustMessage()},
        {2, () => new ShouldIgnoreMessage()},
    };
}