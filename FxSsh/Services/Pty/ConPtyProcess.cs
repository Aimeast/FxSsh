using System;
using System.Runtime.InteropServices;
using static FxSsh.Services.Pty.Native.Win32Api;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Represents an instance of a process.
    /// </summary>
    internal sealed class Process : IDisposable
    {
        public Process(STARTUPINFOEX startupInfo, PROCESS_INFORMATION processInfo)
        {
            StartupInfo = startupInfo;
            ProcessInfo = processInfo;
        }

        public STARTUPINFOEX StartupInfo { get; }
        public PROCESS_INFORMATION ProcessInfo { get; }

        /// <summary>
        /// Returns the process exit code via GetExitCodeProcess. Returns
        /// 259 (STILL_ACTIVE) if queried before the process terminates.
        /// </summary>
        public uint ExitCode
        {
            get
            {
                if (ProcessInfo.hProcess == IntPtr.Zero)
                    return 0;
                GetExitCodeProcess(ProcessInfo.hProcess, out uint code);
                return code;
            }
        }

        #region IDisposable Support

        private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // dispose managed state (managed objects).
                }

                // dispose unmanaged state

                // Free the attribute list
                if (StartupInfo.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(StartupInfo.lpAttributeList);
                    Marshal.FreeHGlobal(StartupInfo.lpAttributeList);
                }

                // Close process and thread handles
                if (ProcessInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandle(ProcessInfo.hProcess);
                }
                if (ProcessInfo.hThread != IntPtr.Zero)
                {
                    CloseHandle(ProcessInfo.hThread);
                }

                disposedValue = true;
            }
        }

        ~Process()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // use the following line if the finalizer is overridden above.
            GC.SuppressFinalize(this);
        }

        #endregion
    }

    /// <summary>
    /// Support for starting and configuring processes.
    /// </summary>
    /// <remarks>
    /// Possible to replace with managed code? The key is being able to provide the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute
    /// </remarks>
    static class ProcessFactory
    {
        /// <summary>
        /// Start and configure a process. The return value represents the process and should be disposed.
        /// </summary>
        internal static Process Start(string command, IntPtr attributes, IntPtr hPC)
        {
            var startupInfo = ConfigureProcessThread(hPC, attributes);
            var processInfo = RunProcess(ref startupInfo, command);
            return new Process(startupInfo, processInfo);
        }

        private static STARTUPINFOEX ConfigureProcessThread(IntPtr hPC, IntPtr attributes)
        {
            // this method implements the behavior described in https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session#preparing-for-creation-of-the-child-process

            var lpSize = IntPtr.Zero;
            var success = InitializeProcThreadAttributeList(
                lpAttributeList: IntPtr.Zero,
                dwAttributeCount: 1,
                dwFlags: 0,
                lpSize: ref lpSize
            );
            if (success || lpSize == IntPtr.Zero) // we're not expecting `success` here, we just want to get the calculated lpSize
            {
                throw new InvalidOperationException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
            }

            var startupInfo = new STARTUPINFOEX();
            startupInfo.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            success = InitializeProcThreadAttributeList(
                lpAttributeList: startupInfo.lpAttributeList,
                dwAttributeCount: 1,
                dwFlags: 0,
                lpSize: ref lpSize
            );
            if (!success)
            {
                throw new InvalidOperationException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
            }

            success = UpdateProcThreadAttribute(
                lpAttributeList: startupInfo.lpAttributeList,
                dwFlags: 0,
                attribute: attributes,
                lpValue: hPC,
                cbSize: (IntPtr)IntPtr.Size,
                lpPreviousValue: IntPtr.Zero,
                lpReturnSize: IntPtr.Zero
            );
            if (!success)
            {
                throw new InvalidOperationException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
            }

            return startupInfo;
        }

        private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
        {
            int securityAttributeSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
            var pSec = new SECURITY_ATTRIBUTES { nLength = securityAttributeSize };
            var tSec = new SECURITY_ATTRIBUTES { nLength = securityAttributeSize };
            var success = CreateProcess(
                lpApplicationName: null,
                lpCommandLine: commandLine,
                lpProcessAttributes: ref pSec,
                lpThreadAttributes: ref tSec,
                bInheritHandles: false,
                dwCreationFlags: EXTENDED_STARTUPINFO_PRESENT,
                lpEnvironment: IntPtr.Zero,
                lpCurrentDirectory: null,
                lpStartupInfo: ref sInfoEx,
                lpProcessInformation: out PROCESS_INFORMATION pInfo
            );
            if (!success)
            {
                throw new InvalidOperationException("Could not create process. " + Marshal.GetLastWin32Error());
            }

            return pInfo;
        }
    }
}

