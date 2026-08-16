using System;

namespace FxSsh.Services
{
    public class PtyArgs
    {
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

        public SessionChannel Channel { get; private set; }
        public string Terminal { get; private set; }
        public uint HeightPx { get; private set; }
        public uint HeightRows { get; private set; }
        public uint WidthPx { get; private set; }
        public uint WidthChars { get; private set; }
        public byte[] Modes { get; private set; }
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}

