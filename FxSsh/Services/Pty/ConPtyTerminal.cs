using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using static FxSsh.Services.Pty.Native.Win32Api;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Windows pseudo-terminal backend built on the Win32 Pseudo Console
    /// (ConPTY, Windows 10 1809+). Implements <see cref="ITerminal"/>.
    /// In a "real" project this could be some other UI.
    /// </summary>
    public sealed class ConPtyTerminal : ITerminal
    {
        private PseudoConsolePipe inputPipe;
        private PseudoConsolePipe outputPipe;
        private PseudoConsole pseudoConsole;
        private Process process;
        private FileStream writer;
        private FileStream reader;
        private readonly SemaphoreSlim _inputLock = new(1, 1);

        public ConPtyTerminal(string command, int windowWidth, int windowHeight)
        {
            // The pseudo console outputs UTF-8 bytes; ensure the host console
            // interprets them as UTF-8 rather than the legacy OEM code page.
            SetConsoleOutputCP(CP_UTF8);

            inputPipe = new PseudoConsolePipe();
            outputPipe = new PseudoConsolePipe();
            pseudoConsole = PseudoConsole.Create(inputPipe.ReadSide, outputPipe.WriteSide, windowWidth, windowHeight);
            process = ProcessFactory.Start(command, PseudoConsole.PseudoConsoleThreadAttribute, pseudoConsole.Handle);
            writer = new FileStream(inputPipe.WriteSide, FileAccess.Write);
            reader = new FileStream(outputPipe.ReadSide, FileAccess.Read);
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler<uint> CloseReceived;

        /// <summary>
        /// Start the psuedoconsole and run the process as shown in
        /// https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session#creating-the-pseudoconsole
        /// </summary>
        public void Run()
        {
            // Wait on the process handle directly (avoids System.Diagnostics.Process.Exited
            // which can silently fail due to insufficient handle access rights).
            ThreadPool.RegisterWaitForSingleObject(
                new AutoResetEvent(false)
                {
                    SafeWaitHandle = new SafeWaitHandle(process.ProcessInfo.hProcess, ownsHandle: false)
                },
                (state, timedOut) =>
                {
                    // CancelIoEx forcibly terminates the pending ReadFile and unblocks
                    // reader.Read(). Unlike Dispose(), it works even while SafeFileHandle
                    // has an outstanding reference count from the active read.
                    try { CancelIoEx(outputPipe.ReadSide, IntPtr.Zero); } catch { }
                },
                null, Timeout.Infinite, executeOnlyOnce: true);

            Task.Run(async () =>
            {
                var buf = new byte[1024 * 4];
                try
                {
                    while (true)
                    {
                        int length;
                        try
                        {
                            length = await reader.ReadAsync(buf.AsMemory());
                        }
                        catch (IOException)
                        {
                            break;    // ERROR_OPERATION_ABORTED from CancelIoEx after process exit
                        }
                        catch (OperationCanceledException)
                        {
                            break;    // .NET 10 OSFileStreamStrategy maps cancelled I/O to this
                        }
                        catch (ObjectDisposedException)
                        {
                            break;
                        }
                        if (length == 0)
                            break;
                        // Copy: the read buffer is reused on the next ReadAsync,
                        // but the async subscriber (Channel.SendDataAsync) may
                        // still be awaiting when that happens.
                        DataReceived?.Invoke(this, buf.AsSpan(0, length).ToArray());
                    }
                }
                finally
                {
                    try { writer.Dispose(); } catch { }
                    // Report the real shell exit code rather than a hard-coded 0,
                    // so the SSH "exit-status" channel request reflects `exit N`.
                    // GetExitCodeProcess may briefly return STILL_ACTIVE (259)
                    // if the wait callback hasn't fired yet; collapse that to 0
                    // to avoid leaking an implementation artifact to the client.
                    var code = process.ExitCode;
                    CloseReceived?.Invoke(this, code == 259 ? 0u : code);
                }
            });
        }

        /// <summary>
        /// Write SSH channel input into the pseudo console asynchronously.
        /// Called from the SSH ConnectionService message loop task (via the
        /// channel DataReceived event); never blocks it. Writes are serialized
        /// so interleaved SSH packets cannot interleave bytes in the PTY input
        /// stream, and the slice is copied because the async write holds the
        /// memory across an await while the SSH receive buffer is recycled.
        /// </summary>
        public async Task OnInputAsync(ReadOnlyMemory<byte> data)
        {
            var copy = data.ToArray();
            await _inputLock.WaitAsync();
            try
            {
                await writer.WriteAsync(copy);
                await writer.FlushAsync();
            }
            finally
            {
                _inputLock.Release();
            }
        }

        public void OnClose()
        {
            try { writer.Dispose(); } catch { }
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(process.ProcessInfo.dwProcessId);
                if (!proc.HasExited)
                    proc.Kill();   // Terminate the child shell to avoid orphan processes
            }
            catch { }
        }

        /// <summary>
        /// Resizes the pseudo console window, causing the child process to receive
        /// a WINDOW_BUFFER_SIZE_EVENT and re-lay out its output.
        /// </summary>
        public void Resize(int width, int height)
        {
            pseudoConsole.Resize(width, height);
        }

        private void DisposeResources(params IDisposable[] disposables)
        {
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }
        }

        public void Dispose()
        {
            DisposeResources(reader, writer, process, pseudoConsole, outputPipe, inputPipe);
        }
    }
}

