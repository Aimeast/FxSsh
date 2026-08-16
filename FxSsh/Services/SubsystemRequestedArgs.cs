using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="ConnectionService.SubsystemRequested"/>: raised
    /// when the peer requests an SSH subsystem (RFC 4254 section 6.5), e.g.
    /// "sftp". The host sets <see cref="Agreed"/> to accept; the core then
    /// replies SSH_MSG_CHANNEL_SUCCESS or SSH_MSG_CHANNEL_FAILURE.
    /// </summary>
    public class SubsystemRequestedArgs
    {
        public SubsystemRequestedArgs(SessionChannel channel, string name, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            Name = name;
            AttachedUserAuthArgs = userAuthArgs;
        }

        public SessionChannel Channel { get; private set; }

        /// <summary>Subsystem name, e.g. "sftp".</summary>
        public string Name { get; private set; }

        public UserAuthArgs AttachedUserAuthArgs { get; private set; }

        /// <summary>Set to true to accept the subsystem request.</summary>
        public bool Agreed { get; set; }
    }
}
