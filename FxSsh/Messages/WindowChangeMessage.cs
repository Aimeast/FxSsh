using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents an SSH_MSG_CHANNEL_REQUEST with request type "window-change"
    /// (RFC 4254 section 6.7), which reports that the terminal size of the
    /// client-side session has changed.
    /// </summary>
    public class WindowChangeMessage : ChannelRequestMessage
    {
        /// <summary>
        /// Gets the new terminal width in columns.
        /// </summary>
        public uint WidthColumns { get; private set; }

        /// <summary>
        /// Gets the new terminal height in rows.
        /// </summary>
        public uint HeightRows { get; private set; }

        /// <summary>
        /// Gets the new terminal width in pixels.
        /// </summary>
        public uint WidthPixels { get; private set; }

        /// <summary>
        /// Gets the new terminal height in pixels.
        /// </summary>
        public uint HeightPixels { get; private set; }

        /// <summary>
        /// Loads the terminal size fields from the payload, after the base
        /// request fields read by <see cref="ChannelRequestMessage"/>.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            WidthColumns = reader.ReadUInt32();
            HeightRows = reader.ReadUInt32();
            WidthPixels = reader.ReadUInt32();
            HeightPixels = reader.ReadUInt32();
        }
    }
}
