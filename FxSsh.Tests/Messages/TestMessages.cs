using System;
using System.Text;

namespace FxSsh.Tests.Messages
{
    /// <summary>
    /// Shared helper for building raw message payloads the way a peer would
    /// put them on the wire: the leading message number followed by the
    /// message-specific fields.
    /// </summary>
    internal static class TestMessages
    {
        public static SshDataWriter Payload(byte messageNumber) => new SshDataWriter().Write(messageNumber);

        public static byte[] UintBytes(uint value) =>
            new SshDataWriter().Write(value).ToByteArray();

        public static byte[] StringBytes(string value, Encoding encoding) =>
            new SshDataWriter().Write(value, encoding).ToByteArray();
    }
}
