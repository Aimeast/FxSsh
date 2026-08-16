using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using static FxSsh.Services.Pty.Native.UnixApi;
using SystemProcess = System.Diagnostics.Process;

namespace FxSsh.Services.Pty
{
    /// <summary>
    /// Linux pseudo-terminal backend on the devpts / ptmx pair.
    /// Implements <see cref="ITerminal"/> via the classic POSIX sequence:
    /// posix_openpt -> grantpt/unlockpt -> ptsname_r -> configure termios,
    /// then start the shell as a session leader whose controlling terminal
    /// is the pty slave (setsid + shell redirection, no fork in-process).
    /// The parent keeps the master and bridges bytes with the SSH channel.
    /// </summary>
    public sealed class UnixTerminal : ITerminal
    {
        private readonly string _command;
        private readonly byte[] _modes;
        private int _masterFd = -1;
        private int _slaveFd = -1;
        private SystemProcess _process;
        private readonly SemaphoreSlim _inputLock = new(1, 1);
        private int _closed;

        public UnixTerminal(string command, int windowWidth, int windowHeight, byte[] modes)
        {
            ArgumentNullException.ThrowIfNull(command);
            _command = command;
            _modes = modes;

            _masterFd = posix_openpt(O_RDWR | O_NOCTTY);
            if (_masterFd < 0)
                throw new InvalidOperationException("posix_openpt failed: " + Marshal.GetLastPInvokeError());
            try
            {
                if (grantpt(_masterFd) != 0)
                    throw new InvalidOperationException("grantpt failed: " + Marshal.GetLastPInvokeError());
                if (unlockpt(_masterFd) != 0)
                    throw new InvalidOperationException("unlockpt failed: " + Marshal.GetLastPInvokeError());

                var nameBuf = Marshal.AllocHGlobal(256);
                string slavePath;
                try
                {
                    if (ptsname_r(_masterFd, nameBuf, 256) != 0)
                        throw new InvalidOperationException("ptsname_r failed: " + Marshal.GetLastPInvokeError());
                    slavePath = Marshal.PtrToStringAnsi(nameBuf);
                }
                finally
                {
                    Marshal.FreeHGlobal(nameBuf);
                }

                _slaveFd = open(slavePath, O_RDWR | O_NOCTTY);
                if (_slaveFd < 0)
                    throw new InvalidOperationException("open slave failed: " + Marshal.GetLastPInvokeError());

                ConfigureTermios(_slaveFd, modes);
                SetWindowSize(_masterFd, windowWidth, windowHeight);

                SpawnChild(slavePath);
            }
            catch
            {
                CleanupFds();
                throw;
            }
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler<uint> CloseReceived;

        /// <summary>
        /// Start the master read loop; when the slave side hangs up (child
        /// exited) the loop reaps the child and reports its exit code.
        /// </summary>
        public void Run()
        {
            Task.Run(() =>
            {
                var buf = new byte[1024 * 4];
                var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
                try
                {
                    var ptr = handle.AddrOfPinnedObject();
                    while (true)
                    {
                        int length = read(_masterFd, ptr, buf.Length);
                        if (length <= 0)
                            break;   // EIO / EOF after the slave side is closed
                        DataReceived?.Invoke(this, buf.AsSpan(0, length).ToArray());
                    }
                }
                finally
                {
                    handle.Free();
                }

                // Slave side closed: the shell exited; report its real exit code.
                int code = 0;
                try
                {
                    _process?.WaitForExit();
                    if (_process != null && _process.HasExited)
                        code = _process.ExitCode;
                }
                catch
                {
                }
                CloseReceived?.Invoke(this, (uint)Math.Max(0, code));
            });
        }

        /// <summary>
        /// Write SSH channel input to the pty master. Writes are serialized
        /// so interleaved SSH packets cannot interleave bytes in the input
        /// stream; the slice is copied because the async write holds the
        /// memory across an await while the SSH receive buffer is recycled.
        /// </summary>
        public async Task OnInputAsync(ReadOnlyMemory<byte> data)
        {
            var copy = data.ToArray();
            await _inputLock.WaitAsync();
            try
            {
                var handle = GCHandle.Alloc(copy, GCHandleType.Pinned);
                try
                {
                    var ptr = handle.AddrOfPinnedObject();
                    var written = 0;
                    while (written < copy.Length)
                    {
                        var n = write(_masterFd, IntPtr.Add(ptr, written), copy.Length - written);
                        if (n <= 0)
                            break;
                        written += n;
                    }
                }
                finally
                {
                    handle.Free();
                }
            }
            finally
            {
                _inputLock.Release();
            }
        }

        public void OnClose()
        {
            // SIGHUP the child shell first so the slave side hangs up and the
            // master read loop unblocks; then close the master.
            if (Interlocked.Exchange(ref _closed, 1) == 0)
            {
                if (_process != null && !_process.HasExited)
                {
                    try { kill(_process.Id, 1 /* SIGHUP */); } catch { }
                }
                CleanupFds();
            }
        }

        /// <summary>
        /// Resize the terminal; TIOCSWINSZ makes the kernel send SIGWINCH to
        /// the foreground process group of the slave (like SIGWINCH / resize).
        /// </summary>
        public void Resize(int width, int height)
        {
            SetWindowSize(_masterFd, width, height);
        }

        public void Dispose()
        {
            OnClose();
            _inputLock.Dispose();
        }

        /// <summary>
        /// Configure the slave side as a normal interactive terminal suitable
        /// for SSH sessions. The client keeps its own terminal raw and
        /// forwards raw bytes, so the server must provide echo and line
        /// editing (ICANON | ECHO | ECHOE | ECHOK) plus output post-
        /// processing (OPOST | ONLCR so a newline returns the cursor),
        /// keeping ISIG so the client's Ctrl+C maps to SIGINT in the shell.
        /// RFC 4254 section 8 mode opcodes are applied on top.
        /// </summary>
        private static void ConfigureTermios(int fd, byte[] modes)
        {
            if (tcgetattr(fd, out Termios t) != 0)
                throw new InvalidOperationException("tcgetattr failed: " + Marshal.GetLastPInvokeError());

            // Normal interactive mode: echo and line editing live on the
            // server side (the SSH client disables its local echo).
            t.c_iflag |= ICRNL | IUTF8;             // CR -> NL on input, UTF-8 aware erase
            t.c_oflag |= OPOST | ONLCR;             // NL -> CR+NL on output
            t.c_lflag |= ISIG | ICANON | ECHO | ECHOE | ECHOK;
            t.c_cflag |= CS8 | CREAD;

            ApplyModes(ref t, modes);

            if (tcsetattr(fd, TCSANOW, ref t) != 0)
                throw new InvalidOperationException("tcsetattr failed: " + Marshal.GetLastPInvokeError());
        }

        /// <summary>
        /// RFC 4254 section 8 terminal modes: a byte string of (opcode, uint32
        /// big-endian value) pairs, terminated by opcode 0. Opcodes 1-18 map
        /// to c_cc control characters, 30-42/50-64 to input/local flags, and
        /// 128/129 to input/output speeds.
        /// </summary>
        private static void ApplyModes(ref Termios t, byte[] modes)
        {
            if (modes == null || modes.Length == 0)
                return;

            int i = 0;
            while (i < modes.Length)
            {
                int opcode = modes[i++];
                if (opcode == 0)
                    break;
                if (i + 4 > modes.Length)
                    break;
                uint value = (uint)((modes[i] << 24) | (modes[i + 1] << 16) | (modes[i + 2] << 8) | modes[i + 3]);
                i += 4;

                if (opcode >= 1 && opcode <= 18)
                {
                    // VINTR..VDISCARD; the RFC opcode numbering matches the
                    // c_cc index (VINTR=0 .. VDISCARD=17).
                    t.c_cc[opcode - 1] = (byte)value;
                    continue;
                }

                // Input flags (opcodes 30-42) -> c_iflag.
                uint iflag;
                switch (opcode)
                {
                    case 30: iflag = IGNPAR; break;
                    case 31: iflag = PARMRK; break;
                    case 32: iflag = INPCK; break;
                    case 33: iflag = ISTRIP; break;
                    case 34: iflag = INLCR; break;
                    case 35: iflag = IGNCR; break;
                    case 36: iflag = ICRNL; break;
                    case 37: iflag = IUCLC; break;
                    case 38: iflag = IXON; break;
                    case 39: iflag = IXANY; break;
                    case 40: iflag = IXOFF; break;
                    case 41: iflag = IMAXBEL; break;
                    case 42: iflag = IUTF8; break;
                    default: iflag = 0; break;
                }
                if (iflag != 0)
                {
                    if (value != 0)
                        t.c_iflag |= iflag;
                    else
                        t.c_iflag &= ~iflag;
                    continue;
                }

                // Local flags (opcodes 50-64) -> c_lflag.
                uint lflag;
                switch (opcode)
                {
                    case 50: lflag = ISIG; break;
                    case 51: lflag = ICANON; break;
                    case 53: lflag = ECHO; break;
                    case 54: lflag = ECHOE; break;
                    case 55: lflag = ECHOK; break;
                    case 56: lflag = ECHONL; break;
                    case 57: lflag = NOFLSH; break;
                    case 58: lflag = TOSTOP; break;
                    case 60: lflag = ECHOCTL; break;
                    case 61: lflag = ECHOKE; break;
                    default:
                        // XCASE(52), ITOSTOP(59), PENDIN(62), FLUSHO(63),
                        // EXTPROC(64) and reserved opcodes are ignored.
                        continue;
                }
                if (value != 0)
                    t.c_lflag |= lflag;
                else
                    t.c_lflag &= ~lflag;
            }
        }

        private static void SetWindowSize(int fd, int width, int height)
        {
            var ws = new Winsize
            {
                ws_col = (ushort)Math.Max(0, width),
                ws_row = (ushort)Math.Max(0, height),
            };
            ioctl(fd, TIOCSWINSZ, ref ws);
        }

        /// <summary>
        /// Start the shell as a session leader with the pty slave as its
        /// controlling terminal. Instead of forking in-process (unsafe in a
        /// multi-threaded .NET process), spawn `setsid /bin/sh -c "exec
        /// {shell} <{slave} >{slave} 2>&1"`: the shell opens the slave itself
        /// (no O_NOCTTY), which makes it the controlling terminal, then execs
        /// the requested command. The server keeps only the master.
        /// </summary>
        private void SpawnChild(string slavePath)
        {
            var shellPath = ResolveShellPath();

            var psi = new ProcessStartInfo
            {
                FileName = "setsid",
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("-w");
            psi.ArgumentList.Add("/bin/sh");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add($"exec {shellPath} <{slavePath} >{slavePath} 2>&1");
            psi.Environment["TERM"] = "xterm";

            try
            {
                _process = SystemProcess.Start(psi);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to start shell: " + ex.Message, ex);
            }
            if (_process == null)
                throw new InvalidOperationException("Failed to start shell process.");

            // The server no longer needs the slave fd; the shell holds it as
            // its controlling terminal. Closing it lets the master read
            // return EIO once the shell exits.
            close(_slaveFd);
            _slaveFd = -1;
        }

        /// <summary>
        /// Resolve the shell path: use the command as-is when it contains a
        /// slash, otherwise probe the common login-shell locations. Falls
        /// back to /bin/sh.
        /// </summary>
        private string ResolveShellPath()
        {
            string path = _command;
            if (!path.Contains('/'))
            {
                foreach (var candidate in new[] { "/bin/", "/usr/bin/", "/usr/local/bin/" })
                {
                    if (System.IO.File.Exists(candidate + _command))
                    {
                        path = candidate + _command;
                        break;
                    }
                }
                if (path.Contains('/') == false)
                    path = "/bin/sh";
            }
            return path;
        }

        private void CleanupFds()
        {
            if (_masterFd >= 0)
            {
                close(_masterFd);
                _masterFd = -1;
            }
            if (_slaveFd >= 0)
            {
                close(_slaveFd);
                _slaveFd = -1;
            }
        }
    }
}

