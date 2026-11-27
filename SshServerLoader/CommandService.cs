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
        private readonly object _writeLocker = new();
        private Task _pendingWrites = Task.CompletedTask;
        private long _pendingBytes;

        // Cap on bytes accepted from SSH but not yet written to the child's
        // stdin. The bounded channel alone does not bound the serialized wait
        // chain in front of it.
        private const int MaximumPendingBytes = 8 * 1024 * 1024;

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
        /// ConnectionService message loop task, so it must never block: a
        /// blocking write would prevent the same loop from delivering the
        /// WINDOW_ADJUST that drains the opposite direction and deadlock a
        /// full-duplex stream. The copy is queued behind a serialized chain
        /// and bounded by <see cref="MaximumPendingBytes"/>; overflow closes
        /// stdin instead of growing memory.
        /// </summary>
        public void OnData(ReadOnlyMemory<byte> data)
        {
            if (data.Length == 0)
                return;

            if (Interlocked.Add(ref _pendingBytes, data.Length) > MaximumPendingBytes)
            {
                Interlocked.Add(ref _pendingBytes, -data.Length);
                OnClose();
                return;
            }

            var copy = data.ToArray();
            lock (_writeLocker)
            {
                _pendingWrites = QueueAfterAsync(_pendingWrites, copy, data.Length);
            }
        }

        private async Task QueueAfterAsync(Task previous, byte[] data, int length)
        {
            try { await previous.ConfigureAwait(false); } catch { }

            try
            {
                await _stdinChannel.Writer.WriteAsync(data).ConfigureAwait(false);
            }
            catch
            {
                // Channel completed during teardown.
            }
            finally
            {
                Interlocked.Add(ref _pendingBytes, -length);
            }
        }

        public void OnClose()
        {
            Task pending;
            lock (_writeLocker)
                pending = _pendingWrites;

            _ = CompleteAfterAsync(pending);
        }

        private async Task CompleteAfterAsync(Task pending)
        {
            try { await pending.ConfigureAwait(false); } catch { }
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
