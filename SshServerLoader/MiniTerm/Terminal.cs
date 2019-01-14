using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MiniTerm
{
    /// <summary>
    /// The UI of the terminal. It's just a normal console window, but we're managing the input/output.
    /// In a "real" project this could be some other UI.
    /// </summary>
    public sealed class Terminal : IDisposable
    {
        private PseudoConsolePipe inputPipe;
        private PseudoConsolePipe outputPipe;
        private PseudoConsole pseudoConsole;
        private Process process;
        private FileStream writer;
        private FileStream reader;

        public Terminal(string command, int windowWidth, int windowHeight)
        {
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
            // copy all pseudoconsole output to stdout
            Task.Run(() =>
            {
                var proc = System.Diagnostics.Process.GetProcessById(process.ProcessInfo.dwProcessId);

                var buf = new byte[1024];
                while (!proc.HasExited)
                {
                    var length = reader.Read(buf, 0, buf.Length);
                    if (length == 0)
                        break;
                    DataReceived?.Invoke(this, buf.Take(length).ToArray());
                }
                CloseReceived?.Invoke(this, 0);
            });
        }

        public void OnInput(byte[] data)
        {
            writer.Write(data, 0, data.Length);
            writer.Flush();
        }

        public void OnClose()
        {
            writer.WriteByte(0x03);
            writer.Flush();
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
