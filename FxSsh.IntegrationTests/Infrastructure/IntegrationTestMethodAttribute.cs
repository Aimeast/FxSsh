using System;
using System.Runtime.CompilerServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Marks a test as a real-client OpenSSH integration test (grouping and
    /// documentation only, filterable via TestCategory=Integration). The only
    /// gate is the OpenSSH client availability check in
    /// <see cref="IntegrationGuard.RequireSshClient"/>.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class IntegrationTestMethodAttribute : TestMethodAttribute
    {
        public IntegrationTestMethodAttribute(
            [CallerFilePath] string callerFilePath = "",
            [CallerLineNumber] int callerLineNumber = -1)
            : base(callerFilePath, callerLineNumber)
        {
        }
    }
}
