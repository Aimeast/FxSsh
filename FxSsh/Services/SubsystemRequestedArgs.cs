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
        /// <summary>
        /// Initializes a new instance of the <see cref="SubsystemRequestedArgs"/> class.
        /// </summary>
        /// <param name="channel">The session channel the subsystem was requested on.</param>
        /// <param name="name">The subsystem name, e.g. "sftp".</param>
        /// <param name="userAuthArgs">Authentication details of the user attached to the channel.</param>
        public SubsystemRequestedArgs(SessionChannel channel, string name, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            Name = name;
            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>
        /// Gets the session channel the subsystem was requested on.
        /// </summary>
        public SessionChannel Channel { get; private set; }

        /// <summary>Subsystem name, e.g. "sftp".</summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user attached to the
        /// channel.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }

        /// <summary>Set to true to accept the subsystem request.</summary>
        public bool Agreed { get; set; }
    }
}
