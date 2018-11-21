using System.Text;

namespace FxSsh.Messages.Connection
{
    public class PtyRequestMessage : ChannelRequestMessage
    {
        public string Terminal = "";
        public uint widthChars = 0;
        public uint heightRows = 0;
        public uint widthPx = 0;
        public uint heightPx = 0;
        public string modes = "";

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);

            Terminal = reader.ReadString(Encoding.ASCII);
            widthChars = reader.ReadUInt32();
            heightRows = reader.ReadUInt32();
            widthPx = reader.ReadUInt32();
            heightPx = reader.ReadUInt32();
            modes = reader.ReadString(Encoding.ASCII);
        }
    }
}
