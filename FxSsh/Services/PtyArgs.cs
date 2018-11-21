using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class PtyArgs
    {
        public PtyArgs(SessionChannel channel, string terminal, uint heightPx, uint heightRows, uint widthPx, uint widthChars, string modes, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(terminal != null);
            Contract.Requires(modes != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            Terminal = terminal;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;
            Modes = modes;

            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public string Terminal { get; private set; }
        public uint HeightPx { get; private set; }
        public uint HeightRows { get; private set; }
        public uint WidthPx { get; private set; }
        public uint WidthChars { get; private set; }
        public string Modes { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
