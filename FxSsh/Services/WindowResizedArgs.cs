using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class WindowResizedArgs
    {
        public WindowResizedArgs(SessionChannel channel, uint heightPx, uint heightRows, uint widthPx, uint widthChars, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            HeightPx = heightPx;
            HeightRows = heightRows;
            WidthPx = widthPx;
            WidthChars = widthChars;

            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public uint HeightPx { get; private set; }
        public uint HeightRows { get; private set; }
        public uint WidthPx { get; private set; }
        public uint WidthChars { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
