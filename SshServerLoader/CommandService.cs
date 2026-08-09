using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace SshServerLoader
{
    /// <summary>
    /// Bridges an SSH session channel to a child process (exec / subsystem /
    /// git). Both directions are async: stdout is pumped with ReadAsync and
    /// SSH->stdin data is queued into a Channel drained by a single async
    /// writer, so no thread is blocked on the process pipes. OnData stays
    /// synchronous (enqueue only) so the SSH message loop task never waits on
    /// a pipe write, and the Channel preserves packet order.
    /// </summary>
    public class CommandService
    {
        private Process _process = null;
        private ProcessStartInfo _startInfo = null;
        private readonly Channel<byte[]> _stdinChannel =
            Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true });

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
            _ = MessageLoopAsync();
            _ = StdinLoopAsync();
        }

        /// <summary>
        /// Queue SSH channel input for the child's stdin. Called on the SSH
        /// ConnectionService message loop task (via the channel DataReceived
        /// event); only enqueues, never blocks. The slice is copied because
        /// the async writer consumes it after the SSH receive buffer has been
        /// recycled.
        /// </summary>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            try
            {
                _stdinChannel.Writer.TryWrite(data.ToArray());
            }
            catch
            {
            }
        }

        public void OnClose()
        {
            _stdinChannel.Writer.TryComplete();
            try { _process.StandardInput.BaseStream.Close(); } catch { }
        }

        /// <summary>
        /// Single async writer draining the stdin queue in arrival order;
        /// serializes WriteAsync so interleaved SSH packets cannot corrupt
        /// the process input stream.
        /// </summary>
        private async Task StdinLoopAsync()
        {
            try
            {
                var stream = _process.StandardInput.BaseStream;
                await foreach (var data in _stdinChannel.Reader.ReadAllAsync())
                {
                    await stream.WriteAsync(data);
                    await stream.FlushAsync();
                }
            }
            catch
            {
                // Stdin closed (process exited or OnClose); nothing to do.
            }
        }

        private async Task MessageLoopAsync()
        {
            var bytes = new byte[1024 * 64];
            try
            {
                while (true)
                {
                    var len = await _process.StandardOutput.BaseStream.ReadAsync(bytes.AsMemory());
                    if (len <= 0)
                        break;

                    // Copy: the read buffer is reused on the next ReadAsync,
                    // but the async subscriber (Channel.SendDataAsync) may
                    // still be awaiting when that happens.
                    var data = bytes.AsSpan(0, len).ToArray();
                    DataReceived?.Invoke(this, data);
                }
            }
            catch
            {
                // Pipes closed (e.g. process killed); report EOF/exit below.
            }
            EofReceived?.Invoke(this, EventArgs.Empty);
            CloseReceived?.Invoke(this, (uint)_process.ExitCode);
        }
    }
}
