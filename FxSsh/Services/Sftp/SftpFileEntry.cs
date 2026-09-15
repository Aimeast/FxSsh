namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// One name entry returned in an SSH_FXP_NAME response (draft-ietf-secsh-
    /// filexfer-02, section 7). For READDIR, <see cref="FileName"/> is a
    /// relative name within the directory; for REALPATH it is the canonical
    /// absolute path.
    /// </summary>
    public sealed class SftpFileEntry
    {
        /// <summary>Gets or sets the file name; relative within the directory for READDIR, the canonical absolute path for REALPATH.</summary>
        public string FileName { get; set; }
        /// <summary>Gets or sets the entry's attributes; null when they cannot be determined.</summary>
        public SftpFileAttributes Attributes { get; set; }
    }
}
