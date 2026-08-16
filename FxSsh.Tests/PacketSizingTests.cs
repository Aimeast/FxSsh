using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Tests.Transport;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// RFC 4253 section 6.1: all SSH implementations MUST be able to process
/// packets of up to 35000 bytes total and MUST NOT trust larger pre-auth
/// lengths (which would otherwise allow a memory-exhaustion DoS before
/// authentication). The fork enforces MinimumPacketLength = 12 and
/// MaximumPacketLength = 35000 in the receive path.
///
/// These tests demonstrate the enforcement is REQUIRED: with it, boundary-size
/// packets are accepted, and out-of-range lengths terminate the session
/// instead of being processed (and the server survives the attack).
/// </summary>
public class PacketSizingTests
{
    [Fact]
    public async Task Minimum_length_12_packet_is_accepted()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        // packet_length = 12 is the RFC 4253 section 6 minimum (16 bytes total).
        await client.SendPacketAsync(RawSshClient.FrameWithLength(12, [200]), TestContext.Current.CancellationToken);

        var reply = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        Assert.NotNull(reply);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, reply![0]);

        // Session is still alive: a follow-up packet is also processed.
        await client.SendPacketAsync(RawSshClient.Frame([201]), TestContext.Current.CancellationToken);
        var second = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        Assert.NotNull(second);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, second![0]);
    }

    [Fact]
    public async Task Maximum_length_35000_packet_is_accepted()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        // packet_length = 35000 is the RFC 4253 section 6.1 mandatory maximum.
        var payload = new byte[34980]; // type byte + zeros
        payload[0] = 200;
        await client.SendPacketAsync(RawSshClient.FrameWithLength(35000, payload), TestContext.Current.CancellationToken);

        var reply = await ReadWithTimeoutAsync(client, TimeSpan.FromSeconds(2));
        Assert.NotNull(reply);
        Assert.Equal(RawSshClient.SshMsgUnimplemented, reply![0]);
    }

    [Fact]
    public async Task Oversized_35001_packet_terminates_session_and_server_survives()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        // One byte over the RFC mandatory maximum: must be rejected, not
        // processed (and not hang the server).
        try
        {
            await client.SendPacketAsync(RawSshClient.FrameWithLength(35001, [200]), TestContext.Current.CancellationToken);
        }
        catch (IOException) { } // server may close mid-send
        catch (SocketException) { }

        var closed = await client.WaitForCloseAsync(TimeSpan.FromSeconds(5));
        Assert.True(closed, "Server did not terminate the session after an oversized packet.");

        // DoS protection: the server process is still healthy and accepts new connections.
        using var fresh = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);
        Assert.StartsWith("SSH-2.0-", fresh.ServerVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Undersized_11_packet_terminates_session()
    {
        await using var server = TestSshServer.Start();
        using var client = await RawSshClient.ConnectAsync(server.Port, TestContext.Current.CancellationToken);

        // packet_length = 11 is below the RFC 4253 section 6 minimum of 12.
        try
        {
            await client.SendPacketAsync(RawSshClient.FrameWithLength(11, [200]), TestContext.Current.CancellationToken);
        }
        catch (IOException) { }
        catch (SocketException) { }

        var closed = await client.WaitForCloseAsync(TimeSpan.FromSeconds(5));
        Assert.True(closed, "Server did not terminate the session after an undersized packet.");
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
}
