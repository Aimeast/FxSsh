
namespace SshNet.Services
{
    public class SessionRequestedArgs
    {
        public SessionRequestedArgs(SessionChannel channel, string command)
        {
            Channel = channel;
            CommandText = command;
        }

        public SessionChannel Channel { get; private set; }
        public string CommandText { get; private set; }
    }
}
