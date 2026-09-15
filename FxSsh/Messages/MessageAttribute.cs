using System;

namespace FxSsh.Messages
{
    /// <summary>
    /// Associates an SSH message class with its protocol name and message
    /// number (RFC 4250 section 4.1), e.g. "SSH_MSG_DISCONNECT" and 1. The
    /// mapping serves as protocol documentation; inbound dispatch uses the
    /// compile-time registry instead of reflecting over this attribute.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
    public sealed class MessageAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MessageAttribute"/> class.
        /// </summary>
        /// <param name="name">The SSH protocol name of the message, e.g. "SSH_MSG_KEXINIT".</param>
        /// <param name="number">The SSH message number identifying the message on the wire.</param>
        public MessageAttribute(string name, byte number)
        {
            ArgumentNullException.ThrowIfNull(name);

            Name = name;
            Number = number;
        }

        /// <summary>
        /// Gets the SSH protocol name of the message, e.g. "SSH_MSG_SERVICE_REQUEST".
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the SSH message number identifying the message on the wire.
        /// </summary>
        public byte Number { get; private set; }
    }
}
