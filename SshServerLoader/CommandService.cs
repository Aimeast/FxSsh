using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace SshServerLoader
{
    public class CommandService
    {
        private Process _process = null;
        private ProcessStartInfo _startInfo = null;

        public CommandService(string command, string args)
        {
            _startInfo = new ProcessStartInfo(command, args)
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
                DataReceived?.Invoke(this, data);
            }
            EofReceived?.Invoke(this, EventArgs.Empty);
            CloseReceived?.Invoke(this, (uint)_process.ExitCode);
        }
    }
}
