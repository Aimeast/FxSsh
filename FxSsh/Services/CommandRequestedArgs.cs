using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="ConnectionService.CommandOpened"/>, raised for
    /// "shell", "exec", and "subsystem" channel requests (RFC 4254 section
    /// 6.5). The host sets <see cref="Agreed"/> to accept or reject; the
    /// library then replies SSH_MSG_CHANNEL_SUCCESS or FAILURE.
    /// </summary>
    public class CommandRequestedArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CommandRequestedArgs"/> class.
        /// </summary>
        /// <param name="channel">The session channel the request was sent on.</param>
        /// <param name="type">The request type: "shell", "exec", or "subsystem".</param>
        /// <param name="command">The command to run ("exec"), the subsystem name ("subsystem"), or null for a "shell" request.</param>
        /// <param name="userAuthArgs">Authentication details of the user attached to the channel.</param>
        public CommandRequestedArgs(SessionChannel channel, string type, string command, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            ShellType = type;
            CommandText = command;
            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>
        /// Gets the session channel the request was sent on.
        /// </summary>
        public SessionChannel Channel { get; private set; }

        /// <summary>
        /// Gets the request type: "shell", "exec", or "subsystem".
        /// </summary>
        public string ShellType { get; private set; }

        /// <summary>
        /// Gets the command to execute for an "exec" request or the
        /// subsystem name for a "subsystem" request; null for a "shell"
        /// request.
        /// </summary>
        public string CommandText { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user attached to the
        /// channel.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }

        /// <summary>
        /// Gets or sets a value indicating whether the host accepts the
        /// request. Defaults to false; when the client asked for a reply,
        /// the library answers SSH_MSG_CHANNEL_SUCCESS only if this is true.
        /// </summary>
        public bool Agreed { get; set; }
    }
}
