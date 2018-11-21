using System.Diagnostics.Contracts;

namespace FxSsh.Services
{
    public class EnvironmentArgs
    {
        public EnvironmentArgs(SessionChannel channel, string name, string value, UserauthArgs userauthArgs)
        {
            Contract.Requires(channel != null);
            Contract.Requires(name != null);
            Contract.Requires(value != null);
            Contract.Requires(userauthArgs != null);

            Channel = channel;
            Name = name;
            Value = value;
            AttachedUserauthArgs = userauthArgs;
        }

        public SessionChannel Channel { get; private set; }
        public string Name { get; private set; }
        public string Value { get; private set; }
        public UserauthArgs AttachedUserauthArgs { get; private set; }
    }
}
