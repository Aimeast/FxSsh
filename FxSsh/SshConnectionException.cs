using System;

namespace FxSsh
{
    /// <summary>
    /// Represents the exception thrown when an SSH connection fails or a
    /// protocol violation occurs. Carries the <see cref="DisconnectReason"/>
    /// reported for the disconnect.
    /// </summary>
    public class SshConnectionException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="SshConnectionException"/> class.
        /// </summary>
        public SshConnectionException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="SshConnectionException"/> class with a message and a
        /// disconnect reason.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="disconnectReason">The disconnect reason associated with the exception.</param>
        public SshConnectionException(string message, DisconnectReason disconnectReason = DisconnectReason.None)
            : base(message)
        {
            DisconnectReason = disconnectReason;
        }

        /// <summary>
        /// Initializes a new instance of the
        /// <see cref="SshConnectionException"/> class with a message, a
        /// disconnect reason, and the exception that caused it.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="disconnectReason">The disconnect reason associated with the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public SshConnectionException(string message, DisconnectReason disconnectReason, Exception innerException)
            : base(message, innerException)
        {
            DisconnectReason = disconnectReason;
        }

        /// <summary>
        /// Gets the SSH disconnect reason code associated with this exception.
        /// </summary>
        public DisconnectReason DisconnectReason { get; private set; }

        /// <summary>
        /// Returns a string that describes the disconnect and includes the
        /// disconnect reason.
        /// </summary>
        /// <returns>A string describing the disconnect reason.</returns>
        public override string ToString()
        {
            return string.Format("SSH connection disconnected because {0}", DisconnectReason);
        }
    }
}
