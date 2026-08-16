using System;
using System.Threading.Tasks;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Unified pseudo-terminal abstraction, decoupling an SSH session
    /// channel from the platform backend (Windows ConPTY / Linux devpts).
    /// A terminal is created through <see cref="TerminalFactory.Create"/>.
    /// </summary>
    public interface ITerminal : IDisposable
    {
        /// <summary>
        /// Raised with terminal output bytes (child process stdout/stderr
        /// merged), which the SSH channel should forward to the client.
        /// </summary>
        event EventHandler<byte[]> DataReceived;

        /// <summary>
        /// Raised once when the child process exits, carrying its real
        /// exit code (used for the SSH "exit-status" channel request).
        /// </summary>
        event EventHandler<uint> CloseReceived;

        /// <summary>
        /// Start the output read loop and wait for child process exit.
        /// </summary>
        void Run();

        /// <summary>
        /// Write SSH channel input into the terminal asynchronously.
        /// </summary>
        Task OnInputAsync(ReadOnlyMemory<byte> data);

        /// <summary>
        /// Resize the terminal window; the child process receives a
        /// resize notification (WINDOW_BUFFER_SIZE_EVENT / SIGWINCH).
        /// </summary>
        void Resize(int width, int height);

        /// <summary>
        /// Close the terminal, terminating the child process (if still
        /// running) to avoid orphan processes.
        /// </summary>
        void OnClose();
    }
}

