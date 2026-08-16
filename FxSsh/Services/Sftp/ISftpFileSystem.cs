using System;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// Backend abstraction for the SFTP protocol engine (draft-ietf-secsh-
    /// filexfer-02). The protocol layer parses SSH_FXP_* packets and calls
    /// this interface; a concrete implementation performs the actual file
    /// system operations. This keeps the protocol engine free of disk I/O,
    /// enabling in-memory backends, permission decorators, and unit tests.
    ///
    /// Handles are opaque objects owned by the backend, mirroring the
    /// protocol's handle model: OPEN/OPENDIR return a handle, subsequent
    /// READ/WRITE/FSTAT/FSETSTAT/READDIR/CLOSE operate on it.
    /// </summary>
    public interface ISftpFileSystem
    {
        /// <summary>Open (or create) a file. Maps to SSH_FXP_OPEN.</summary>
        /// <param name="path">Server-side path (virtual, uses '/' separators).</param>
        /// <param name="flags">Open mode flags (SSH_FXF_*).</param>
        /// <param name="attributes">Initial attributes for a created file; may be null.</param>
        ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes);

        /// <summary>Open a directory for listing. Maps to SSH_FXP_OPENDIR.</summary>
        ISftpDirectoryHandle OpenDirectory(string path);

        /// <summary>Retrieve attributes of a path. Maps to SSH_FXP_STAT/LSTAT.</summary>
        /// <param name="path">Server-side path.</param>
        /// <param name="followLinks">True for STAT (follow symbolic links), false for LSTAT.</param>
        SftpFileAttributes GetAttributes(string path, bool followLinks);

        /// <summary>Modify attributes of a path. Maps to SSH_FXP_SETSTAT.</summary>
        void SetAttributes(string path, SftpFileAttributes attributes);

        /// <summary>Remove a file. Maps to SSH_FXP_REMOVE.</summary>
        void RemoveFile(string path);

        /// <summary>Rename a file or directory. Maps to SSH_FXP_RENAME.</summary>
        void Rename(string oldPath, string newPath);

        /// <summary>Create a directory. Maps to SSH_FXP_MKDIR.</summary>
        void MakeDirectory(string path, SftpFileAttributes attributes);

        /// <summary>Remove an empty directory. Maps to SSH_FXP_RMDIR.</summary>
        void RemoveDirectory(string path);

        /// <summary>Canonicalize a path to an absolute form. Maps to SSH_FXP_REALPATH.</summary>
        string RealPath(string path);
    }

    /// <summary>
    /// An open file, returned by <see cref="ISftpFileSystem.OpenFile"/>.
    /// All I/O is positional (like the protocol's READ/WRITE); no stream
    /// cursor is maintained by the caller.
    /// </summary>
    public interface ISftpFileHandle : IDisposable
    {
        /// <summary>Read up to <paramref name="buffer"/>-length bytes at <paramref name="offset"/>. Returns bytes read; 0 at EOF.</summary>
        int Read(long offset, Span<byte> buffer);

        /// <summary>Write <paramref name="data"/> at <paramref name="offset"/>. Extends the file if beyond EOF.</summary>
        void Write(long offset, ReadOnlySpan<byte> data);

        /// <summary>Retrieve the file's attributes. Maps to SSH_FXP_FSTAT.</summary>
        SftpFileAttributes GetAttributes();

        /// <summary>Modify the file's attributes. Maps to SSH_FXP_FSETSTAT.</summary>
        void SetAttributes(SftpFileAttributes attributes);
    }

    /// <summary>
    /// An open directory, returned by <see cref="ISftpFileSystem.OpenDirectory"/>.
    /// Entries are streamed in batches so the protocol engine can page
    /// SSH_FXP_READDIR responses without materializing huge directories.
    /// </summary>
    public interface ISftpDirectoryHandle : IDisposable
    {
        /// <summary>
        /// Return up to <paramref name="maxCount"/> entries. Returns fewer
        /// when exhausted; an empty result means no more entries (the engine
        /// then responds SSH_FX_EOF on the next READDIR).
        /// </summary>
        SftpFileEntry[] ReadEntries(int maxCount);
    }
}
