using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class CommandRequestedArgs
    {
        public CommandRequestedArgs(SessionChannel channel, string type, string command, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(command != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            ShellType = type;
            CommandText = command;
            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public string ShellType { get; private set; }
        public string CommandText { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
