using System;
using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "pty-req" request
    /// (RFC 4254 section 6.2), which allocates a pseudo-terminal for the
    /// channel.
    /// </summary>
    public class PtyRequestMessage : ChannelRequestMessage
    {
        /// <summary>The requested terminal type name (e.g. "vt100").</summary>
        public string Terminal = "";

        /// <summary>The terminal width in characters (columns).</summary>
        public uint widthChars = 0;

        /// <summary>The terminal height in rows.</summary>
        public uint heightRows = 0;

        /// <summary>The terminal width in pixels; zero when unspecified.</summary>
        public uint widthPx = 0;

        /// <summary>The terminal height in pixels; zero when unspecified.</summary>
        public uint heightPx = 0;

        /// <summary>The encoded terminal modes (RFC 4254 section 8); empty when none are requested.</summary>
        public byte[] modes = Array.Empty<byte>();

        /// <summary>Reads the base request fields and the pseudo-terminal parameters from the incoming packet.</summary>
        /// <param name="reader">The reader positioned at the start of the request-specific data.</param>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            Terminal = reader.ReadString(Encoding.ASCII);
            widthChars = reader.ReadUInt32();
            heightRows = reader.ReadUInt32();
            widthPx = reader.ReadUInt32();
            heightPx = reader.ReadUInt32();
            modes = reader.ReadBinary();
        }
    }
}

