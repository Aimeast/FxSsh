using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="ConnectionService.EnvReceived"/>, raised when
    /// the client sends an "env" channel request (RFC 4254 section 6.4) to
    /// set an environment variable for the channel's session.
    /// </summary>
    public class EnvironmentArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentArgs"/> class.
        /// </summary>
        /// <param name="channel">The session channel the variable was set on.</param>
        /// <param name="name">The environment variable name.</param>
        /// <param name="value">The environment variable value.</param>
        /// <param name="userAuthArgs">Authentication details of the user attached to the channel.</param>
        public EnvironmentArgs(SessionChannel channel, string name, string value, UserAuthArgs userAuthArgs)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(name);
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(userAuthArgs);

            Channel = channel;
            Name = name;
            Value = value;
            AttachedUserAuthArgs = userAuthArgs;
        }

        /// <summary>
        /// Gets the session channel the variable was set on.
        /// </summary>
        public SessionChannel Channel { get; private set; }

        /// <summary>
        /// Gets the environment variable name.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the environment variable value.
        /// </summary>
        public string Value { get; private set; }

        /// <summary>
        /// Gets the authentication details of the user attached to the
        /// channel.
        /// </summary>
        public UserAuthArgs AttachedUserAuthArgs { get; private set; }
    }
}
