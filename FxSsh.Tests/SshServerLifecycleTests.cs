using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Regression tests for FxSsh.SshServer teardown. DisposeAsync() used to flip
/// _isDisposed BEFORE calling StopAsync(), and StopAsync() starts with
/// CheckDisposed() - so DisposeAsync() always threw ObjectDisposedException
/// and the listener was never stopped. The fixed contract:
///   - DisposeAsync() stops the server without throwing, and is idempotent
///   - Dispose() also stops the server (async fire-and-forget)
///   - Stop()/StopAsync() on a disposed server still throw
/// </summary>
public class SshServerLifecycleTests
{
    [Fact]
    public async Task DisposeAsync_stops_the_server_without_throwing()
    {
        var port = ReserveEphemeralPort();
        var server = new SshServer(new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-FxSsh-Test"));
        server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
        await server.StartAsync(TestContext.Current.CancellationToken);

        // Regression: this used to throw ObjectDisposedException.
        await server.DisposeAsync();

        // The listener must actually be gone.
        await AssertPortStopsAccepting(port);

        // Idempotent: a second dispose is a no-op, not a throw.
        await server.DisposeAsync();

        // Explicit stop after disposal still throws (existing contract).
        await Assert.ThrowsAsync<ObjectDisposedException>(server.StopAsync);
    }

    [Fact]
    public async Task Dispose_also_stops_the_server()
    {
        var port = ReserveEphemeralPort();
        var server = new SshServer(new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-FxSsh-Test"));
        await server.StartAsync(TestContext.Current.CancellationToken);

        // ReSharper disable once MethodHasAsyncOverload
        server.Dispose(); // async fire-and-forget

        await AssertPortStopsAccepting(port);
    }

    private static async Task AssertPortStopsAccepting(int port)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port);
                await Task.Delay(25); // still accepting - retry
            }
            catch (SocketException)
            {
                return; // connection refused: listener is gone
            }
        }
        Assert.Fail("The server still accepts connections after teardown.");
    }

    private static int ReserveEphemeralPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
