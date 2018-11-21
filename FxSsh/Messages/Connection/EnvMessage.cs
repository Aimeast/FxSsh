using FxSsh.Messages.Connection;
using System.Text;

namespace FxSsh.Messages
{
    public class EnvMessage : ChannelRequestMessage
    {
        public string Name = "";
        public string Value = "";

        protected override void OnLoad(SshDataWorker reader)
        {
            base.OnLoad(reader);

            Name = reader.ReadString(Encoding.ASCII);
            Value = reader.ReadString(Encoding.ASCII);
        }
    }
}
