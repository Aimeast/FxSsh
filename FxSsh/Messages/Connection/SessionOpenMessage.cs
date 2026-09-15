using System;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_OPEN "session" request
    /// (RFC 4254 section 6.1), which opens a channel for a shell, command,
    /// or subsystem.
    /// </summary>
    public class SessionOpenMessage : ChannelOpenMessage
    {
        /// <summary>Reads the base open fields from the incoming packet and verifies the channel type.</summary>
        /// <param name="reader">The reader positioned at the start of the channel-type-specific data.</param>
        /// <exception cref="ArgumentException">Thrown when the channel type is not "session".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (ChannelType != "session")
                throw new ArgumentException(string.Format("Channel type {0} is not valid.", ChannelType));
        }
    }
}
