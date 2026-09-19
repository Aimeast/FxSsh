using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Environment prerequisite check for the real-client OpenSSH tests.
    ///
    /// There is no on/off switch: the project lives in FxSsh.slnx and runs
    /// with the default test run. The only gate is the OpenSSH client
    /// availability check, so a machine without ssh reports skipped tests
    /// instead of failures.
    /// </summary>
    public static class IntegrationGuard
    {
        public static void RequireSshClient()
        {
            if (!OpenSshClient.IsAvailable())
                Assert.Inconclusive("no OpenSSH client (ssh/ssh-keygen) found on PATH");
        }
    }
}
