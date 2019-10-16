using FxSsh.Messages.Connection;

namespace FxSsh.Messages
{
    public class WindowChangeMessage : ChannelRequestMessage
    {
        public uint WidthColumns { get; private set; }
        public uint HeightRows { get; private set; }
        public uint WidthPixels { get; private set; }
        public uint HeightPixels { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);

            WidthColumns = reader.ReadUInt32();
            HeightRows = reader.ReadUInt32();
            WidthPixels = reader.ReadUInt32();
            HeightPixels = reader.ReadUInt32();
        }
    }
}
