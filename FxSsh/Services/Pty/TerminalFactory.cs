using System;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Creates the platform-appropriate <see cref="ITerminal"/> backend:
    /// <see cref="ConPtyTerminal"/> on Windows (Win32 Pseudo Console) and
    /// <see cref="UnixTerminal"/> on Linux (devpts/ptmx).
    /// </summary>
    public static class TerminalFactory
    {
        /// <summary>
        /// Create a pseudo-terminal running <paramref name="command"/> with
        /// the given character-cell window size.
        /// </summary>
        /// <param name="command">Shell command to run (e.g. "bash", "cmd.exe").</param>
        /// <param name="windowWidth">Initial width in character columns.</param>
        /// <param name="windowHeight">Initial height in character rows.</param>
        /// <param name="modes">Optional RFC 4254 section 8 terminal modes byte string
        /// from the SSH pty-req request; applied on Unix. Ignored on Windows.</param>
        public static ITerminal Create(string command, int windowWidth, int windowHeight, byte[] modes = null)
        {
            if (OperatingSystem.IsWindows())
                return new ConPtyTerminal(command, windowWidth, windowHeight);
            return new UnixTerminal(command, windowWidth, windowHeight, modes);
        }
    }
}

