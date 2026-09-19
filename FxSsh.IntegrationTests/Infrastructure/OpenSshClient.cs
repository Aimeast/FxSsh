using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Locates and drives the platform OpenSSH client (ssh, ssh-keygen, sftp,
    /// scp) for the real-client integration tests. Everything runs against
    /// 127.0.0.1 with a throw-away known_hosts file and explicit options, so
    /// nothing touches the developer's real SSH configuration.
    /// </summary>
    internal static class OpenSshClient
    {
        private static readonly Lazy<string> KnownHostsFile = new(() =>
        {
            var path = Path.Combine(Path.GetTempPath(), "fxssh-it-knownhosts-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(path, string.Empty);
            return path;
        });

        public static bool IsAvailable() => FindTool("ssh") != null && FindTool("ssh-keygen") != null;

        public static string SshPath => FindTool("ssh") ?? throw new InvalidOperationException("ssh not found");
        public static string SshKeygenPath => FindTool("ssh-keygen") ?? throw new InvalidOperationException("ssh-keygen not found");

        public static string? FindTool(string name)
        {
            var exeName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? name + ".exe" : name;

            // Explicit override wins: the CI Windows job installs the latest
            // Win32-OpenSSH into a temp dir (the system client may lag the
            // library's catalog, e.g. mlkem needs 9.9+); locally point it at
            // any newer build the same way.
            var overrideDir = Environment.GetEnvironmentVariable("FXSSH_OPENSSH_DIR");
            if (!string.IsNullOrWhiteSpace(overrideDir))
            {
                var candidate = Path.Combine(overrideDir, exeName);
                if (File.Exists(candidate))
                    return candidate;
            }

            // On Windows prefer the system OpenSSH (System32\OpenSSH) over
            // MSYS/Git-Bash builds: the MSYS scp aborts without any output
            // when a remote STAT returns NO_SUCH_FILE (new-file uploads).
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var windir = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
                var candidate = Path.Combine(windir, "System32", "OpenSSH", exeName);
                if (File.Exists(candidate))
                    return candidate;
            }

            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir))
                    continue;

                var candidate = Path.Combine(dir.Trim('"'), exeName);
                if (File.Exists(candidate))
                    return candidate;
            }

            return null;
        }

        /// <summary>
        /// Common ssh/scp/sftp options: never touch the user's known_hosts or
        /// agent, keep logs quiet, and pin IPv4 loopback. The port flag is
        /// lowercase <c>-p</c> for ssh but uppercase <c>-P</c> for scp and
        /// sftp.
        /// </summary>
        public static string CommonOptions(int port, string? identity = null, bool fileTransferTool = false)
        {
            var options = new StringBuilder();
            options.Append(fileTransferTool ? "-P " : "-p ").Append(port).Append(' ');
            options.Append("-4 ");
            options.Append("-o StrictHostKeyChecking=no ");
            options.Append("-o UserKnownHostsFile=\"").Append(KnownHostsFile.Value).Append("\" ");
            options.Append("-o LogLevel=DEBUG2 ");
            options.Append("-o IdentitiesOnly=yes ");
            options.Append("-o PreferredAuthentications=publickey,password ");

            if (identity != null)
                options.Append("-i \"").Append(identity).Append("\" ");

            return options.ToString();
        }

        public static string Target(string username) => $"{username}@127.0.0.1";

        /// <summary>Generate a fresh ECDSA key pair; returns the private key path.</summary>
        public static string GenerateKeyPair(string directory)
        {
            var keyPath = Path.Combine(directory, "test_key");
            var result = RunProcess(SshKeygenPath, $"-t ecdsa -b 256 -N \"\" -f \"{keyPath}\" -C fxssh-integration-test", timeoutMs: 30_000);
            if (result.ExitCode != 0)
                throw new InvalidOperationException($"ssh-keygen failed: {result.StandardError}");

            return keyPath;
        }

        /// <summary>
        /// Create an askpass helper that prints the password, for automating
        /// password authentication (OpenSSH 8.4+ honours
        /// SSH_ASKPASS_REQUIRE=force without a TTY/X11).
        /// </summary>
        public static (string ScriptPath, Dictionary<string, string> Environment) CreatePasswordAuthHelper(string directory, string password)
        {
            var scriptPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Path.Combine(directory, "askpass.cmd")
                : Path.Combine(directory, "askpass.sh");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                File.WriteAllText(scriptPath, $"@echo {password}\r\n");
            }
            else
            {
                File.WriteAllText(scriptPath, $"#!/bin/sh\necho '{password.Replace("'", "'\\''")}'\n");
                File.SetUnixFileMode(scriptPath, UnixFileMode.UserExecute | UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            var env = new Dictionary<string, string>
            {
                ["SSH_ASKPASS"] = scriptPath,
                ["SSH_ASKPASS_REQUIRE"] = "force",
                ["DISPLAY"] = ":0",
            };
            return (scriptPath, env);
        }

        public static RunResult Ssh(string arguments, IReadOnlyDictionary<string, string>? environment = null, string? stdin = null, int timeoutMs = 60_000, string? workingDirectory = null)
            => RunProcess(SshPath, arguments, environment, stdin, timeoutMs, workingDirectory);

        /// <summary>Start a long-running ssh command (e.g. port forwarding) and return the process.</summary>
        public static Process StartSsh(string arguments, IReadOnlyDictionary<string, string>? environment = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = SshPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
            };

            if (environment != null)
            {
                foreach (var (key, value) in environment)
                    psi.EnvironmentVariables[key] = value;
            }

            return Process.Start(psi) ?? throw new InvalidOperationException("failed to start ssh");
        }

        public static RunResult RunProcess(string fileName, string arguments, IReadOnlyDictionary<string, string>? environment = null, string? stdin = null, int timeoutMs = 60_000, string? workingDirectory = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = stdin != null,
                CreateNoWindow = true,
            };

            if (workingDirectory != null)
                psi.WorkingDirectory = workingDirectory;

            if (environment != null)
            {
                foreach (var (key, value) in environment)
                    psi.EnvironmentVariables[key] = value;
            }

            using var process = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {fileName}");

            if (stdin != null)
            {
                process.StandardInput.Write(stdin);
                process.StandardInput.Close();
            }

            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(timeoutMs))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException($"{Path.GetFileName(fileName)} {arguments} did not finish within {timeoutMs} ms");
            }

            return new RunResult(
                process.ExitCode,
                stdout.GetAwaiter().GetResult(),
                stderr.GetAwaiter().GetResult());
        }

        public readonly record struct RunResult(int ExitCode, string StandardOutput, string StandardError);
    }
}
