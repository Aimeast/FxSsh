using System;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Messages;
using FxSsh.Tests.Transport;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// RFC 4253 section 7.1 "first KEX packet follows": a client MAY send its
/// SSH_MSG_KEXINIT and then immediately the first key-exchange packet, without
/// waiting for the server's KEXINIT. When the client's guess of the negotiated
/// algorithms was WRONG, that immediately-following packet is a dummy the
/// server MUST ignore; when the guess was RIGHT, it is a real KEX packet the
/// server MUST process.
///
/// Upstream v1.4 did not honor this flag at all (it hard-coded
/// FirstKexPacketFollows = false and had no ignore-next-packet logic), so a
/// guessing client's dummy packet would be misparsed as a KEX message and the
/// handshake would fail. These tests pin the fork's behavior: they demonstrate
/// the change is REQUIRED for RFC-compliant guessing clients (wrong guess must
/// be ignored) and is CORRECT (a correct guess's packet must not be ignored).
/// </summary>
public class FirstPacketGuessTests
{
    [Fact]
    public async Task Correct_guess_first_kex_packet_is_processed_not_ignored()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        var serverKex = ParseServerKexInit(client.ServerKexInitPayload);
        await client.SendPacketAsync(RawSshClient.Frame(
            BuildClientKexInit(serverKex, wrongGuess: false, firstKexPacketFollows: true)), TestContext.Current.CancellationToken);
        await client.SendPacketAsync(RawSshClient.Frame([200]), TestContext.Current.CancellationToken); // unknown type
        await client.SendPacketAsync(RawSshClient.Frame([201]), TestContext.Current.CancellationToken); // unknown type

        var first = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        var second = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));

        // A correct guess means the packet following KEXINIT is real: neither
        // the 200 nor the 201 packet may be dropped, so both get UNIMPLEMENTED.
        Assert.NotNull(first);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, first![0]);
        Assert.NotNull(second);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, second![0]);
    }

    [Fact]
    public async Task Wrong_guess_dummy_first_packet_is_ignored()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        var serverKex = ParseServerKexInit(client.ServerKexInitPayload);
        await client.SendPacketAsync(RawSshClient.Frame(
            BuildClientKexInit(serverKex, wrongGuess: true, firstKexPacketFollows: true)), TestContext.Current.CancellationToken);
        await client.SendPacketAsync(RawSshClient.Frame([200]), TestContext.Current.CancellationToken); // dummy - must be ignored
        await client.SendPacketAsync(RawSshClient.Frame([201]), TestContext.Current.CancellationToken); // real packet

        var reply = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        Assert.NotNull(reply);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, reply![0]);

        // Only ONE reply may arrive: the dummy (200) was consumed by the
        // ignore-next-packet logic and must not produce a reply. If the fork's
        // guess handling were missing (as in upstream v1.4), the dummy would be
        // misparsed as a message and a second UNIMPLEMENTED would appear here.
        var extra = await ReadWithTimeoutAsync(client, TimeSpan.FromMilliseconds(400));
        Assert.Null(extra);
    }

    [Fact]
    public async Task Without_first_kex_flag_nothing_is_ignored()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        var serverKex = ParseServerKexInit(client.ServerKexInitPayload);
        // Wrong guess but flag NOT set: the ignore logic must stay dormant.
        await client.SendPacketAsync(RawSshClient.Frame(
            BuildClientKexInit(serverKex, wrongGuess: true, firstKexPacketFollows: false)), TestContext.Current.CancellationToken);
        await client.SendPacketAsync(RawSshClient.Frame([200]), TestContext.Current.CancellationToken);
        await client.SendPacketAsync(RawSshClient.Frame([201]), TestContext.Current.CancellationToken);

        var first = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        var second = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));

        Assert.NotNull(first);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, first![0]);
        Assert.NotNull(second);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, second![0]);
    }

    private static async Task<byte[]?> ReadWithTimeoutAsync(RawSshClient client, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            return await client.ReadPacketAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private static byte[] BuildClientKexInit(ParsedKexInit server, bool wrongGuess, bool firstKexPacketFollows)
    {
        // For a wrong guess, put an algorithm the server does not support first
        // in the kex name-list (still listing a supported one so negotiation
        // succeeds) - the server must then conclude the guess was wrong.
        // curve25519-sha256 used to fill this role, but the server now
        // registers it (RFC 8731) as its first preference; diffie-hellman-
        // group14-sha1 is still absent from the registry (only group14-sha256).
        var kexAlgs = wrongGuess
            ? ["diffie-hellman-group14-sha1", .. server.KeyExchangeAlgorithms]
            : server.KeyExchangeAlgorithms;

        var message = new KeyExchangeInitMessage
        {
            KeyExchangeAlgorithms = kexAlgs,
            ServerHostKeyAlgorithms = server.ServerHostKeyAlgorithms,
            EncryptionAlgorithmsClientToServer = server.EncryptionAlgorithmsClientToServer,
            EncryptionAlgorithmsServerToClient = server.EncryptionAlgorithmsServerToClient,
            MacAlgorithmsClientToServer = server.MacAlgorithmsClientToServer,
            MacAlgorithmsServerToClient = server.MacAlgorithmsServerToClient,
            CompressionAlgorithmsClientToServer = server.CompressionAlgorithmsClientToServer,
            CompressionAlgorithmsServerToClient = server.CompressionAlgorithmsServerToClient,
            LanguagesClientToServer = server.LanguagesClientToServer,
            LanguagesServerToClient = server.LanguagesServerToClient,
            FirstKexPacketFollows = firstKexPacketFollows,
            Reserved = 0,
        };
        return message.GetPacket();
    }

    private static ParsedKexInit ParseServerKexInit(byte[] payload)
    {
        var lists = KexInitParser.ParseNameLists(payload);
        return new ParsedKexInit(
            lists[0], lists[1], lists[2], lists[3], lists[4],
            lists[5], lists[6], lists[7], lists[8], lists[9]);
    }

    private sealed record ParsedKexInit(
        string[] KeyExchangeAlgorithms,
        string[] ServerHostKeyAlgorithms,
        string[] EncryptionAlgorithmsClientToServer,
        string[] EncryptionAlgorithmsServerToClient,
        string[] MacAlgorithmsClientToServer,
        string[] MacAlgorithmsServerToClient,
        string[] CompressionAlgorithmsClientToServer,
        string[] CompressionAlgorithmsServerToClient,
        string[] LanguagesClientToServer,
        string[] LanguagesServerToClient);
}
