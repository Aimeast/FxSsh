using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using FxSsh;
using FxSsh.Logging;
using FxSsh.Services;
using FxSsh.Services.Pty;
using FxSsh.Services.Sftp;
using Process = System.Diagnostics.Process;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// An in-process FxSsh server wired for real-client integration tests:
    /// generated host keys, password/publickey/none authentication, exec and
    /// shell (PTY) channels, an SFTP subsystem rooted at a temp directory,
    /// and TCP port forwarding. Mirrors the SshServerLoader sample wiring.
    /// </summary>
    internal sealed class TestSshServer : IAsyncDisposable
    {
        public const string Username = "fxssh-tester";
        public const string Password = "FxSsh-Integration-42";

        private static readonly Lazy<string> RsaHostKeyPem = new(() => KeyGenerator.GenerateRsaKeyPem(2048));
        private static readonly Lazy<string> EcdsaHostKeyPem = new(() => KeyGenerator.GenerateECDsaKeyPem("nistp256"));

        private readonly SshServer _server;
        private readonly object _ptyLock = new();
        private byte[] _ptyModes = [];
        private int _ptyWidth = 120;
        private int _ptyHeight = 40;

        private TestSshServer(SshServer server, string rootPath, int port)
        {
            _server = server;
            RootPath = rootPath;
            Port = port;
        }

        public string RootPath { get; }

        public int Port { get; }

        public bool AllowNoneAuth { get; set; }

        public bool ReadOnlySftp { get; set; }

        /// <summary>Fingerprints accepted for publickey auth (when non-empty, other keys are rejected).</summary>
        public HashSet<string> AcceptedFingerprints { get; } = new(StringComparer.Ordinal);

        public List<(string Method, string Username, string? Fingerprint)> AuthAttempts { get; } = [];

        public List<string> ExecCommands { get; } = [];

        public static async Task<TestSshServer> StartAsync(bool allowNoneAuth = false, bool readOnlySftp = false)
        {
            Log.Configure(new LogOptions
            {
                MinLevel = LogLevel.Trace,
                Sink = new ConsoleLogSink(),
            });

            var rootPath = Path.Combine(Path.GetTempPath(), "fxssh-it-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);

            var port = GetFreePort();
            var server = new SshServer(new StartingInfo(IPAddress.Loopback, port, "SSH-2.0-FxSsh-IT"));
            server.AddHostKey("ecdsa-sha2-nistp256", EcdsaHostKeyPem.Value);
            server.AddHostKey("rsa-sha2-256", RsaHostKeyPem.Value);
            server.AddHostKey("rsa-sha2-512", RsaHostKeyPem.Value);

            var fixture = new TestSshServer(server, rootPath, port)
            {
                AllowNoneAuth = allowNoneAuth,
                ReadOnlySftp = readOnlySftp,
            };

            server.ConnectionAccepted += fixture.OnConnectionAccepted;
            await server.StartAsync();

            return fixture;
        }

        private static int GetFreePort()
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        private void OnConnectionAccepted(object? sender, Session session)
        {
            session.ServiceRegistered += (_, service) =>
            {
                if (service is UserAuthService userAuth)
                {
                    userAuth.EnableNoneAuth = AllowNoneAuth;
                    userAuth.UserAuth += (_, args) =>
                    {
                        lock (AuthAttempts)
                        {
                            AuthAttempts.Add((args.AuthMethod, args.Username, args.Fingerprint));
                        }

                        // The "none" request carries no username in
                        // UserAuthArgs, so none-auth is accepted purely by
                        // the fixture flag.
                        args.Result = args.AuthMethod switch
                        {
                            "none" => AllowNoneAuth,
                            "password" => args.Username == Username && args.Password == Password,
                            "publickey" => AcceptedFingerprints.Contains("*")
                                || AcceptedFingerprints.Contains(args.Fingerprint ?? string.Empty),
                            _ => false,
                        };
                    };
                }
                else if (service is ConnectionService connection)
                {
                    connection.CommandOpened += (_, args) => OnCommandOpened(args);
                    connection.SubsystemRequested += (_, args) => OnSubsystemRequested(args);
                    connection.PtyReceived += (_, args) =>
                    {
                        lock (_ptyLock)
                        {
                            _ptyWidth = (int)args.WidthChars;
                            _ptyHeight = (int)args.HeightRows;
                            _ptyModes = args.Modes;
                        }
                    };
                    connection.TcpForwardRequest += (_, args) => OnTcpForwardRequest(args);
                    connection.TcpForwardRequestReceived += (_, args) => args.Accepted = true;
                }
            };
        }

        private void OnCommandOpened(CommandRequestedArgs args)
        {
            lock (ExecCommands)
            {
                ExecCommands.Add(args.CommandText);
            }

            args.Agreed = true;

            if (args.ShellType == "shell")
            {
                byte[] modes;
                int width, height;
                lock (_ptyLock)
                {
                    modes = _ptyModes;
                    width = _ptyWidth;
                    height = _ptyHeight;
                }

                var shell = OperatingSystem.IsWindows() ? "cmd.exe" : "bash";
                var terminal = TerminalFactory.Create(shell, width, height, modes);

                args.Channel.WindowChange += (_, ee) => terminal.Resize((int)ee.WidthColumns, (int)ee.HeightRows);
                args.Channel.DataReceived += async (_, data) => await TryTerminalInputAsync(terminal, data);
                args.Channel.CloseReceived += (_, _) => terminal.OnClose();
                terminal.DataReceived += async (_, data) => await TrySendChannelDataAsync(args.Channel, data);
                terminal.CloseReceived += (_, exitCode) => args.Channel.SendClose(exitCode);
                terminal.Run();
            }
            else if (args.ShellType == "exec")
            {
                _ = RunExecAsync(args.Channel, args.CommandText);
            }
        }

        private static async Task RunExecAsync(Channel channel, string command)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    CreateNoWindow = true,
                };

                if (OperatingSystem.IsWindows())
                {
                    psi.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
                    psi.ArgumentList.Add("/d");
                    psi.ArgumentList.Add("/s");
                    psi.ArgumentList.Add("/c");
                    psi.ArgumentList.Add(command);
                }
                else
                {
                    psi.FileName = "/bin/sh";
                    psi.ArgumentList.Add("-c");
                    psi.ArgumentList.Add(command);
                }

                using var process = Process.Start(psi);
                if (process == null)
                {
                    channel.SendClose(127);
                    return;
                }

                var pumpOut = PumpStreamAsync(process.StandardOutput.BaseStream, channel);
                var pumpErr = PumpStreamAsync(process.StandardError.BaseStream, channel);
                process.StandardInput.Close();

                await process.WaitForExitAsync();
                await Task.WhenAll(pumpOut, pumpErr);

                channel.SendClose((uint)process.ExitCode);
            }
            catch
            {
                try { channel.SendClose(1); } catch { }
            }
        }

        private static async Task PumpStreamAsync(Stream stream, Channel channel)
        {
            var buffer = new byte[64 * 1024];
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer)) > 0)
                {
                    await TrySendChannelDataAsync(channel, buffer.AsSpan(0, read).ToArray());
                }
            }
            catch
            {
                // Stream torn down with the process; nothing to forward.
            }
        }

        private void OnSubsystemRequested(SubsystemRequestedArgs args)
        {
            if (args.Name != "sftp")
                return;

            args.Agreed = true;
            var sftp = new SftpService(RootPath, ReadOnlySftp);
            sftp.Attach(args.Channel);
        }

        private void OnTcpForwardRequest(TcpRequestArgs args)
        {
            // Handles direct-tcpip channels (-L) and forwarded-tcpip channels
            // opened after an accepted -R global request: everything is local
            // in tests, so both bridge to the requested host:port.
            var forward = new TcpForwardService(args.Host, (int)args.Port, args.OriginatorIP, (int)args.OriginatorPort);
            args.Channel.DataReceived += (_, data) => forward.OnData(data);
            args.Channel.CloseReceived += (_, _) => forward.OnClose();
            forward.DataReceived += async (_, data) => await TrySendChannelDataAsync(args.Channel, data);
            forward.CloseReceived += (_, _) => args.Channel.SendClose();
            forward.Start();
        }

        private static async Task TrySendChannelDataAsync(Channel channel, byte[] data)
        {
            try
            {
                await channel.SendDataAsync(data);
            }
            catch
            {
                // Channel/session torn down mid-send.
            }
        }

        private static async Task TryTerminalInputAsync(ITerminal terminal, ReadOnlyMemory<byte> data)
        {
            try
            {
                await terminal.OnInputAsync(data);
            }
            catch
            {
                // Terminal disposed during teardown.
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _server.DisposeAsync();
            try
            {
                Directory.Delete(RootPath, recursive: true);
            }
            catch
            {
                // Best effort cleanup; the OS temp dir wins eventually.
            }
        }
    }
}
