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
            // Clients without a local TTY (CI jobs, spawned processes) send
            // pty-req with 0 columns/rows; CreatePseudoConsole rejects those
            // with E_INVALIDARG, so clamp to a sane default (RFC 4254 6.2
            // makes the initial size advisory; window-change resizes later).
            if (windowWidth <= 0)
                windowWidth = 80;
            if (windowHeight <= 0)
                windowHeight = 24;

            if (OperatingSystem.IsWindows())
                return new ConPtyTerminal(command, windowWidth, windowHeight);
            return new UnixTerminal(command, windowWidth, windowHeight, modes);
        }
    }
}

