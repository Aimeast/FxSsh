using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Renci.SshNet;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// End-to-end interoperability with a real, widely-used SSH client library
/// (SSH.NET). This is the baseline "is the fork's transport sound at all"
/// check: a full handshake (version exchange, KEXINIT negotiation, key
/// exchange, auth) plus a large data round-trip through a channel.
///
/// The 1 MiB payload is far larger than the server's channel packet size
/// (Session.MaximumSshPacketSize = 32 KiB), so the round-trip exercises the
/// channel-data packet path - the sizing behavior the fork changed - with a
/// real client, and would fail if the server advertised or handled window /
/// packet sizes incorrectly.
/// </summary>
public class SshNetInteropTests
{
    [Fact]
    public async Task SshNet_client_full_handshake_and_large_data_round_trip()
    {
        await using var server = TestSshServer.Start();

        using var client = new SshClient(new ConnectionInfo(
            "127.0.0.1", server.Port, "tester",
            new PasswordAuthenticationMethod("tester", "pw")));
        client.Connect();

        await using var shell = client.CreateShellStream("xterm", 80, 24, 800, 600, 8192);

        // Use a payload well above the channel packet size, and a small poll
        // loop: SSH.NET's ShellStream is a buffered pipe, so we flush explicitly
        // and poll DataAvailable instead of blocking on Read.
        var payload = RandomNumberGenerator.GetBytes(256 * 1024);
        shell.Write(payload, 0, payload.Length);
        shell.Flush();

        var echoed = await ReadAllEchoedAsync(shell, payload.Length);

        Assert.Equal(payload, echoed);

        client.Disconnect();

        // Server-side teardown must complete cleanly for a client-initiated close.
        await server.DisconnectedTask.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    private static async Task<byte[]> ReadAllEchoedAsync(ShellStream shell, int expectedLength)
    {
        var received = new MemoryStream();
        var buffer = new byte[64 * 1024];
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);

        while (received.Length < expectedLength && DateTime.UtcNow < deadline)
        {
            if (shell.DataAvailable)
            {
                var n = shell.Read(buffer, 0, buffer.Length);
                if (n <= 0) break;
                received.Write(buffer, 0, n);
            }
            else
            {
                await Task.Delay(25);
            }
        }

        Assert.True(received.Length == expectedLength, $"Timed out waiting for the echoed payload (got {received.Length}/{expectedLength} bytes).");
        return received.ToArray();
    }
}
