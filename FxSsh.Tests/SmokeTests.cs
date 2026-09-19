using System;
using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests
{
    [TestClass]
    public sealed class SmokeTests
    {
        [TestMethod]
        public void InternalsVisibleTo_grants_access_to_internal_pool()
        {
            // SshBuffers is internal to FxSsh; being able to touch it proves
            // the friend-assembly grant (strong-named) is wired up correctly.
            Assert.IsInstanceOfType(SshBuffers.Packets, typeof(ArrayPool<byte>));
        }
    }
}
