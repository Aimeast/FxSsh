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
        public string FileName { get; set; }
        public SftpFileAttributes Attributes { get; set; }
    }
}
