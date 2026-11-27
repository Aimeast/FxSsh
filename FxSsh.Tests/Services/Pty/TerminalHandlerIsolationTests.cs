using System;
using System.Threading.Tasks;
using FxSsh.Services.Pty;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Services.Pty
{
    /// <summary>
    /// The Unix pty read loop runs on a bare thread whose unhandled exception
    /// would terminate the whole process, so event handlers must be isolated:
    /// a throwing DataReceived handler must not stop the loop, and the exit
    /// notification must still fire afterwards.
    /// </summary>
    [TestClass]
    public sealed class TerminalHandlerIsolationTests
    {
        [TestMethod]
        public async Task DataReceived_handler_exception_does_not_kill_the_read_loop()
        {
            if (!OperatingSystem.IsLinux())
                Assert.Inconclusive("UnixTerminal requires a Linux pty");

            using var terminal = TerminalFactory.Create("/bin/cat", 80, 24);
            var sawSecondEcho = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var first = true;
            terminal.DataReceived += (_, _) =>
            {
                if (first)
                {
                    first = false;
                    // Mirrors a send into a channel torn down mid-session.
                    throw new ObjectDisposedException("channel");
                }
                sawSecondEcho.TrySetResult(true);
            };
            var closed = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);
            terminal.CloseReceived += (_, code) => closed.TrySetResult(code);

            terminal.Run();
            await terminal.OnInputAsync("first"u8.ToArray());
            await Task.Delay(300);   // let the first echo hit the throwing handler
            await terminal.OnInputAsync("second"u8.ToArray());

            // The loop survived the throwing handler and still delivers data.
            await sawSecondEcho.Task.WaitAsync(TimeSpan.FromSeconds(10));

            terminal.OnClose();
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }
}
