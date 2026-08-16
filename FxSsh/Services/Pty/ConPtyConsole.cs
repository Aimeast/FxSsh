using System;
using Microsoft.Win32.SafeHandles;
using static FxSsh.Services.Pty.Native.Win32Api;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Utility functions around the new Pseudo Console APIs
    /// </summary>
    internal sealed class PseudoConsole : IDisposable
    {
        public static readonly IntPtr PseudoConsoleThreadAttribute = (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE;

        public IntPtr Handle { get; }

        private PseudoConsole(IntPtr handle)
        {
            this.Handle = handle;
        }

        internal static PseudoConsole Create(SafeFileHandle inputReadSide, SafeFileHandle outputWriteSide, int width, int height)
        {
            var createResult = CreatePseudoConsole(
                new COORD { X = (short)width, Y = (short)height },
                inputReadSide, outputWriteSide,
                0, out IntPtr hPC);
            if (createResult != 0)
            {
                throw new InvalidOperationException("Could not create psuedo console. Error Code " + createResult);
            }
            return new PseudoConsole(hPC);
        }

        /// <summary>
        /// Notifies the child pseudo console of a host console window size change,
        /// causing the child process (cmd.exe, powershell, etc.) to receive a
        /// WINDOW_BUFFER_SIZE_EVENT / SIGWINCH and re-lay out its output.
        /// </summary>
        internal void Resize(int width, int height)
        {
            var resizeResult = ResizePseudoConsole(this.Handle, new COORD { X = (short)width, Y = (short)height });
            if (resizeResult != 0)
            {
                throw new InvalidOperationException("Could not resize pseudo console. Error Code " + resizeResult);
            }
        }

        public void Dispose()
        {
            ClosePseudoConsole(Handle);
        }
    }

    /// <summary>
    /// A pipe used to talk to the pseudoconsole, as described in:
    /// https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
    /// </summary>
    /// <remarks>
    /// We'll have two instances of this class, one for input and one for output.
    /// </remarks>
    internal sealed class PseudoConsolePipe : IDisposable
    {
        public readonly SafeFileHandle ReadSide;
        public readonly SafeFileHandle WriteSide;

        public PseudoConsolePipe()
        {
            if (!CreatePipe(out ReadSide, out WriteSide, IntPtr.Zero, 0))
            {
                throw new InvalidOperationException("failed to create pipe");
            }
        }

        #region IDisposable

        void Dispose(bool disposing)
        {
            if (disposing)
            {
                ReadSide?.Dispose();
                WriteSide?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}

