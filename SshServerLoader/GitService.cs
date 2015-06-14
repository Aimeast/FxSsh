using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SshServerLoader
{

    public class GitService
    {
        private Process _process = null;
        private ProcessStartInfo _startInfo = null;

        public GitService(string command, string project)
        {
            var args = Path.Combine(@"F:\Dev\GitTest\", project + ".git");

            _startInfo = new ProcessStartInfo(Path.Combine(@"D:\PortableGit\libexec\git-core", command + ".exe"), args)
            {
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
        }

        public event EventHandler<byte[]> DataReceived;
        public event EventHandler EofReceived;
        public event EventHandler<uint> CloseReceived;

        public void Start()
        {
            _process = Process.Start(_startInfo);
            Task.Run(() => MessageLoop());
        }

        public void OnData(byte[] data)
        {
            _process.StandardInput.BaseStream.Write(data, 0, data.Length);
            _process.StandardInput.BaseStream.Flush();
        }

        public void OnClose()
        {
            _process.StandardInput.BaseStream.Close();
        }

        private void MessageLoop()
        {
            var bytes = new byte[1024 * 64];
            while (true)
            {
                var len = _process.StandardOutput.BaseStream.Read(bytes, 0, bytes.Length);
                if (len <= 0)
                    break;

                var data = bytes.Length != len
                    ? bytes.Take(len).ToArray()
                    : bytes;
                if (DataReceived != null)
                    DataReceived(this, data);
            }
            if (EofReceived != null)
                EofReceived(this, EventArgs.Empty);
            if (CloseReceived != null)
                CloseReceived(this, (uint)_process.ExitCode);
        }
    }
}
