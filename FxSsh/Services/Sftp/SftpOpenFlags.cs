using System;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// Flags for opening a file (SSH_FXF_* in draft-ietf-secsh-filexfer-02,
    /// section 6.3). Maps 1:1 onto the protocol pflags field.
    /// </summary>
    [Flags]
    public enum SftpOpenFlags
    {
        /// <summary>Open the file for reading.</summary>
        Read = 0x00000001,

        /// <summary>Open the file for writing.</summary>
        Write = 0x00000002,

        /// <summary>Force all writes to append to the end of the file.</summary>
        Append = 0x00000004,

        /// <summary>Create the file if it does not already exist.</summary>
        Create = 0x00000008,

        /// <summary>Truncate an existing file to zero length; MUST be combined with <see cref="Create"/>.</summary>
        Truncate = 0x00000010,

        /// <summary>Fail if the file already exists; MUST be combined with <see cref="Create"/>.</summary>
        Exclusive = 0x00000020,
    }
}
