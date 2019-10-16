using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class WindowChangeArgs
    {
        public WindowChangeArgs(SessionChannel channel, uint widthColumns, uint heightRows, uint widthPixels, uint heightPixels)
        {
            Contract.Requires(channel != null);

            Channel = channel;
            WidthColumns = widthColumns;
            HeightRows = heightRows;
            WidthPixels = widthPixels;
            HeightPixels = heightPixels;
        }

        public SessionChannel Channel { get; private set; }
        public uint WidthColumns { get; private set; }
        public uint HeightRows { get; private set; }
        public uint WidthPixels { get; private set; }
        public uint HeightPixels { get; private set; }
    }
}
