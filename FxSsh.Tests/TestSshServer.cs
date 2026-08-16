using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using FxSsh.Services;

namespace FxSsh.Tests;

/// <summary>
/// Test harness: a real FxSsh server on an ephemeral loopback port with an
/// ECDSA host key, an auth policy that accepts any user/password, and an echo
/// service on "shell" channels. <see cref="DisconnectedTask"/> completes when
/// the first session tears down.
/// </summary>
public sealed class TestSshServer : IAsyncDisposable
{
    private readonly SshServer _server;
    private readonly TaskCompletionSource _disconnected;

    // RSA host key generation is comparatively slow; generate once per process.
    private static readonly string RsaHostKeyPem = KeyGenerator.GenerateRsaKeyPem(2048);

    private TestSshServer(SshServer server, int port, TaskCompletionSource disconnected)
    {
        _server = server;
        Port = port;
        _disconnected = disconnected;
    }

    public int Port { get; }

    /// <summary>Completes when any session has disconnected (clean teardown check).</summary>
    public Task DisconnectedTask => _disconnected.Task;

    /// <summary>
    /// Register a host key PEM for a host key algorithm (passthrough to
    /// <see cref="SshServer.AddHostKey"/>), so plugin host-key tests can add
    /// e.g. "ssh-ed25519" alongside the built-in keys.
    /// </summary>
    public void AddHostKey(string type, string pem) => _server.AddHostKey(type, pem);

    public static TestSshServer Start(bool allHostKeyAlgorithms = false)
    {
        var port = ReserveEphemeralPort();
        var disconnected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SshServer(new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-FxSsh-Test"));

        if (allHostKeyAlgorithms)
        {
            // Register every default PublicKeyAlgorithm plus the pluggable
            // "ssh-rsa" (LegacyRsaKey in the test project), so host-key
            // algorithm tests can force each one via the client's offer list.
            server.AddHostKey("rsa-sha2-256", RsaHostKeyPem);
            server.AddHostKey("rsa-sha2-512", RsaHostKeyPem);
            server.AddHostKey("ssh-rsa", RsaHostKeyPem);
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
            server.AddHostKey("ecdsa-sha2-nistp384", KeyGenerator.GenerateECDsaKeyPem("nistp384"));
            server.AddHostKey("ecdsa-sha2-nistp521", KeyGenerator.GenerateECDsaKeyPem("nistp521"));
        }
        else
        {
            server.AddHostKey("ecdsa-sha2-nistp256", KeyGenerator.GenerateECDsaKeyPem("nistp256"));
        }

        server.ConnectionAccepted += (_, session) =>
        {
            session.Disconnected += (_, _) => disconnected.TrySetResult();
            session.ServiceRegistered += (_, service) =>
            {
                switch (service)
                {
                    case UserAuthService auth:
                        // Accept any user/password so SSH.NET can get past auth.
                        auth.UserAuth += (_, e) => e.Result = true;
                        break;
                    case ConnectionService conn:
                        // Echo service on "shell" channels: everything the client
                        // writes comes back, exercising the channel-data packet path.
                        conn.CommandOpened += (_, e) =>
                        {
                            e.Agreed = true;
                            var channel = e.Channel;
                            channel.DataReceived += (_, data) => channel.SendData(data);
                            // Close once the client signals EOF: real clients
                            // (e.g. OpenSSH) send CHANNEL_EOF when their stdin is
                            // exhausted and then wait for the server to close.
                            channel.EofReceived += (_, _) => channel.SendClose(0);
                            channel.CloseReceived += (_, _) => channel.SendClose();
                        };
                        break;
                }
            };
        };

        server.StartAsync().GetAwaiter().GetResult();
        return new TestSshServer(server, port, disconnected);
    }

    private static int ReserveEphemeralPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        await _server.DisposeAsync();
    }
}
