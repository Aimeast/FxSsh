using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="ConnectionService.PtyReceived"/>, raised when
    /// the client sends a "pty-req" channel request (RFC 4254 section 6.2)
    /// asking for a pseudo-terminal on a session channel.
    /// </summary>
    public class PtyArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PtyArgs"/> class.
        /// </summary>
        /// <param name="channel">The session channel the PTY was requested on.</param>
        /// <param name="terminal">The terminal emulation name reported by the client, e.g. "xterm".</param>
        /// <param name="heightPx">The terminal height in pixels; 0 means unspecified.</param>
        /// <param name="heightRows">The terminal height in character rows.</param>
        /// <param name="widthPx">The terminal width in pixels; 0 means unspecified.</param>
        /// <param name="widthChars">The terminal width in character columns.</param>
        /// <param name="modes">The encoded terminal modes (RFC 4254 section 8): opcode/argument pairs terminated by a TTY_OP_END opcode.</param>
        /// <param name="userAuthArgs">Authentication details of the user attached to the channel.</param>
        public PtyArgs(SessionChannel channel, string terminal, uint heightPx, uint heightRows, uint widthPx, uint widthChars, byte[] modes, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(terminal);
            ArgumentNullException.ThrowIfNull(modes);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            Terminal = terminal;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;
            Modes = modes;

            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>
        /// Gets the session channel the PTY was requested on.
        /// </summary>
        public SessionChannel Channel { get; private set; }

        /// <summary>
        /// Gets the terminal emulation name reported by the client, e.g.
        /// "vt100" or "xterm".
        /// </summary>
        public string Terminal { get; private set; }

        /// <summary>
        /// Gets the terminal height in pixels; 0 means unspecified.
        /// </summary>
        public uint HeightPx { get; private set; }

        /// <summary>
        /// Gets the terminal height in character rows.
        /// </summary>
        public uint HeightRows { get; private set; }

        /// <summary>
        /// Gets the terminal width in pixels; 0 means unspecified.
        /// </summary>
        public uint WidthPx { get; private set; }

        /// <summary>
        /// Gets the terminal width in character columns.
        /// </summary>
        public uint WidthChars { get; private set; }

        /// <summary>
        /// Gets the encoded terminal modes (RFC 4254 section 8): a sequence
        /// of opcode/argument pairs terminated by the TTY_OP_END opcode (0).
        /// </summary>
        public byte[] Modes { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user attached to the
        /// channel.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}

