using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Renci.SshNet;
using Xunit;

namespace FxSsh.Tests;

/// <summary>
/// Shared plumbing for the client-interop tests: builds an SSH.NET
/// ConnectionInfo, prunes an SSH.NET algorithm dictionary down to a single
/// algorithm (forcing the client to offer only it), and round-trips a payload
/// through an echo shell. Used by AlgorithmMatrixInteropTests.
/// </summary>
internal static class AlgorithmInteropHelper
{
    public static ConnectionInfo CreateConnectionInfo(int port)
        => new("127.0.0.1", port, "tester", new PasswordAuthenticationMethod("tester", "pw"));

    /// <summary>
    /// Prune a default SSH.NET algorithm dictionary (holding SSH.NET's own
    /// instances) down to the single algorithm under test, forcing the client
    /// to offer only it.
    /// </summary>
    public static void KeepOnly<TValue>(IDictionary<string, TValue> algorithms, string keep)
    {
        foreach (var name in algorithms.Keys.ToList().Where(name => name != keep))
        {
            algorithms.Remove(name);
        }

        Assert.True(algorithms.ContainsKey(keep),
            $"SSH.NET does not ship the '{keep}' algorithm.");
    }

    /// <summary>
    /// Write a random payload to the echo shell and read it back in full,
    /// proving channel data flowed through the negotiated cipher/MAC.
    /// </summary>
    public static async Task EchoRoundTripAsync(ShellStream shell, int bytes)
    {
        var payload = RandomNumberGenerator.GetBytes(bytes);
        shell.Write(payload, 0, payload.Length);
        shell.Flush();

        var received = new MemoryStream();
        var buffer = new byte[8192];
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (received.Length < payload.Length && DateTime.UtcNow < deadline)
        {
            if (shell.DataAvailable)
            {
                var n = shell.Read(buffer, 0, buffer.Length);
                if (n <= 0) break;
                received.Write(buffer, 0, n);
            }
            else
            {
                await Task.Delay(10);
            }
        }

        Assert.Equal(payload, received.ToArray());
    }
}
