using System.Text;

namespace FxSsh.Messages.Connection
{
    public class ShellRequestMessage : ChannelRequestMessage
    {
        protected override void OnLoad(SshDataWorker reader)
        {
        }
    }
}
