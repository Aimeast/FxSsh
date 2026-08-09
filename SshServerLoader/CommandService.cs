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
    /// SSH->stdin data is queued into a BOUNDED Channel drained by a single
    /// async writer, so no thread is blocked on the process pipes and memory
    /// is capped even if the child stops reading stdin. When the queue is
    /// full, OnData blocks the SSH message loop task (stopping the SSH
    /// receive-window replenish), propagating backpressure to the client.
    /// </summary>
    public class CommandService
    {
        private Process _process = null;
        private ProcessStartInfo _startInfo = null;
        // Bounded queue: at most 16 in-flight 64KiB chunks (~1 MiB), so a
        // child that stops reading stdin cannot balloon memory. FullMode.Wait
        // makes Writer.Write block (backpressure) instead of dropping data.
        private static readonly BoundedChannelOptions StdinChannelOptions = new(16)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        };

        private readonly Channel<byte[]> _stdinChannel = Channel.CreateBounded<byte[]>(StdinChannelOptions);

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
        /// ConnectionService message loop task. The queue is bounded
        /// (FullMode.Wait), so a blocking Write here is the intended
        /// backpressure path: if the child stops reading stdin, the message
        /// loop task pauses, which stops replenishing the SSH receive window
        /// and throttles the client. OnClose completes the queue, unblocking
        /// any pending write. The slice is copied because the async writer
        /// consumes it after the SSH receive buffer has been recycled.
        /// </summary>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            try
            {
                // Synchronous wait on the bounded channel: the message loop
                // task has no SynchronizationContext, so GetAwaiter().GetResult()
                // safely blocks until the stdin writer frees a slot
                // (backpressure) or the queue is completed (teardown).
                _stdinChannel.Writer.WriteAsync(data.ToArray()).AsTask().GetAwaiter().GetResult();
            }
            catch (ChannelClosedException)
            {
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
