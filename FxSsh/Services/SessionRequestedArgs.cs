
namespace SshNet.Services
{
    public class SessionRequestedArgs
    {
        public SessionRequestedArgs(SessionChannel channel, string command, UserauthArgs userauthArgs)
        {
            Channel = channel;
            CommandText = command;
            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public string CommandText { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
