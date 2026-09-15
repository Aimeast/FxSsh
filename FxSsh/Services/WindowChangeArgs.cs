using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="Channel.WindowChange"/>, raised when the client
    /// sends a "window-change" channel request (RFC 4254 section 6.7) to
    /// report a new terminal size for the channel's pseudo-terminal.
    /// </summary>
    public class WindowChangeArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WindowChangeArgs"/> class.
        /// </summary>
        /// <param name="channel">The channel whose terminal was resized.</param>
        /// <param name="widthColumns">The new terminal width in columns.</param>
        /// <param name="heightRows">The new terminal height in rows.</param>
        /// <param name="widthPixels">The new terminal width in pixels.</param>
        /// <param name="heightPixels">The new terminal height in pixels.</param>
        public WindowChangeArgs(SessionChannel channel, uint widthColumns, uint heightRows, uint widthPixels, uint heightPixels)
        {
            ArgumentNullException.ThrowIfNull(channel);

            Channel = channel;
            WidthColumns = widthColumns;
            HeightRows = heightRows;
            WidthPixels = widthPixels;
            HeightPixels = heightPixels;
        }

        /// <summary>
        /// Gets the channel whose terminal was resized.
        /// </summary>
        public SessionChannel Channel { get; private set; }

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
    }
}
