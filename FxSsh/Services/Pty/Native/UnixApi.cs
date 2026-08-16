using System;
using System.Runtime.InteropServices;

namespace FxSsh.Services.Pty.Native
{
    /// <summary>
    /// PInvoke signatures for the Linux libc pty / tty APIs used by
    /// <see cref="UnixTerminal"/> (posix_openpt, fork, setsid, Termios,
    /// TIOCSWINSZ). Constants follow the asm-generic headers shared by
    /// x86_64 and aarch64; glibc and musl expose the same Termios layout.
    /// </summary>
    static class UnixApi
    {
        internal const int O_RDWR = 0x0002;
        internal const int O_NOCTTY = 0x0100;

        // asm-generic/ioctls.h
        internal const int TIOCSWINSZ = 0x5414;
        internal const int TCSANOW = 0;

        // Termios input flags
        internal const uint IGNBRK = 0x0001, BRKINT = 0x0002, IGNPAR = 0x0004, PARMRK = 0x0008, INPCK = 0x0010,
            ISTRIP = 0x0020, INLCR = 0x0040, IGNCR = 0x0080, ICRNL = 0x0100, IUCLC = 0x0200, IXON = 0x0400,
            IXANY = 0x0800, IXOFF = 0x1000, IMAXBEL = 0x2000, IUTF8 = 0x4000;
        // output flags
        internal const uint OPOST = 0x0001;
        internal const uint ONLCR = 0x0004;
        // control flags
        internal const uint CSIZE = 0x0030, CS8 = 0x0030, PARENB = 0x0100, CREAD = 0x0080;
        // local flags
        internal const uint ISIG = 0x0001, ICANON = 0x0002, XCASE = 0x0004, ECHO = 0x0008, ECHOE = 0x0010,
            ECHOK = 0x0020, ECHONL = 0x0040, NOFLSH = 0x0080, TOSTOP = 0x0100, ECHOCTL = 0x0200,
            ECHOKE = 0x0800, IEXTEN = 0x8000;

        [StructLayout(LayoutKind.Sequential)]
        internal struct Winsize
        {
            public ushort ws_row;
            public ushort ws_col;
            public ushort ws_xpixel;
            public ushort ws_ypixel;
        }

        /// <summary>
        /// glibc/musl user-space Termios (NCCS = 32): 16 bytes of flags,
        /// c_line, c_cc[32], then ispeed/ospeed. The kernel layout (NCCS=19)
        /// is translated by tcgetattr/tcsetattr.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct Termios
        {
            public uint c_iflag;
            public uint c_oflag;
            public uint c_cflag;
            public uint c_lflag;
            public byte c_line;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] c_cc;
            public uint c_ispeed;
            public uint c_ospeed;
        }

        [DllImport("libc", SetLastError = true)]
        internal static extern int posix_openpt(int flags);

        [DllImport("libc", SetLastError = true)]
        internal static extern int grantpt(int fd);

        [DllImport("libc", SetLastError = true)]
        internal static extern int unlockpt(int fd);

        [DllImport("libc", SetLastError = true)]
        internal static extern int ptsname_r(int fd, IntPtr buf, int buflen);

        [DllImport("libc", SetLastError = true)]
        internal static extern int open(string pathname, int flags);

        [DllImport("libc", SetLastError = true)]
        internal static extern int ioctl(int fd, int request, IntPtr arg);

        [DllImport("libc", SetLastError = true)]
        internal static extern int ioctl(int fd, int request, ref Winsize ws);

        [DllImport("libc", SetLastError = true)]
        internal static extern int tcgetattr(int fd, out Termios Termios_p);

        [DllImport("libc", SetLastError = true)]
        internal static extern int tcsetattr(int fd, int optional_actions, ref Termios Termios_p);

        [DllImport("libc", SetLastError = true)]
        internal static extern int close(int fd);

        [DllImport("libc", SetLastError = true)]
        internal static extern int read(int fd, IntPtr buf, int count);

        [DllImport("libc", SetLastError = true)]
        internal static extern int write(int fd, IntPtr buf, int count);

        [DllImport("libc", SetLastError = true)]
        internal static extern int kill(int pid, int sig);
    }
}

