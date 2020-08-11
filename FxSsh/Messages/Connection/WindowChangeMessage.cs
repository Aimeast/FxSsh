namespace FxSsh.Messages.Connection
{
    public class WindowChangeMessage : ChannelRequestMessage
    {
        public uint widthChars = 0;
        public uint heightRows = 0;
        public uint widthPx = 0;
        public uint heightPx = 0;

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);

            widthChars = reader.ReadUInt32();
            heightRows = reader.ReadUInt32();
            widthPx = reader.ReadUInt32();
            heightPx = reader.ReadUInt32();
        }
    }
}
