using System;
using System.Text;

namespace FxSsh.Messages.Connection
{
    public class PTYRequestMessage : ChannelRequestMessage
    {
        public string TermEnv { get; private set; }
        public UInt32 TermWidth { get; private set; }
        public UInt32 TermHeight { get; private set; }
        public UInt32 TermWidthPixels { get; private set; }
        public UInt32 TermHeightPixels { get; private set; }
        public string TermModes { get; private set; }

        protected override void OnLoad(SshDataWorker reader)
        {
            /*
              byte      SSH_MSG_CHANNEL_REQUEST
              uint32    recipient channel
              string    "pty-req"
              boolean   want_reply
              string    TERM environment variable value (e.g., vt100)
              uint32    terminal width, characters (e.g., 80)
              uint32    terminal height, rows (e.g., 24)
              uint32    terminal width, pixels (e.g., 640)
              uint32    terminal height, pixels (e.g., 480)
              string    encoded terminal modes
              */
            base.OnLoad(reader);

            TermEnv = reader.ReadString(Encoding.ASCII);
            TermWidth = reader.ReadUInt32();
            TermHeight = reader.ReadUInt32();
            TermWidthPixels = reader.ReadUInt32();
            TermHeightPixels = reader.ReadUInt32();
            TermModes = reader.ReadString(Encoding.ASCII);
        }
    }

}
