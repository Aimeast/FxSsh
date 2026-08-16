using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// Default <see cref="ISftpFileSystem"/> backed by the local disk, rooted
    /// at a single directory (a chroot-style jail). All client paths are
    /// resolved against <paramref name="rootPath"/> and are prevented from
    /// escaping it (draft-ietf-secsh-filexfer-02, section 6.2).
    ///
    /// Errors surface as the corresponding .NET exceptions; the protocol
    /// engine maps them to SSH_FX_* status codes. This is the one place
    /// platform-specific path handling lives.
    /// </summary>
    public sealed class LocalFileSystem : ISftpFileSystem
    {
        private readonly string _rootPath;
        private readonly bool _readOnly;

        public LocalFileSystem(string rootPath)
            : this(rootPath, readOnly: false)
        {
        }

        public LocalFileSystem(string rootPath, bool readOnly)
        {
            ArgumentNullException.ThrowIfNull(rootPath);

            // Normalize once: ensure a trailing separator so the escape check
            // ("starts with root") cannot be fooled by prefix siblings.
            _rootPath = Path.GetFullPath(rootPath + Path.DirectorySeparatorChar);
            _readOnly = readOnly;
        }

        /// <summary>
        /// Create a file system rooted at the current user's home directory
        /// (the SFTP default starting location). Cross-platform: the user
        /// profile folder on Windows, $HOME elsewhere. Falls back to the
        /// filesystem root if no home can be determined - never to the
        /// process/working directory.
        /// </summary>
        public static LocalFileSystem FromUserHome()
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrEmpty(home))
                home = OperatingSystem.IsWindows() ? @"C:\" : "/";
            return new LocalFileSystem(home);
        }

        /// <summary>
        /// Backend-level read-only guard: every mutating operation throws
        /// <see cref="UnauthorizedAccessException"/>, which the protocol
        /// engine maps to SSH_FX_PERMISSION_DENIED. This is a second line of
        /// defence behind the engine's own read-only check, so a read-only
        /// backend stays read-only even if used without the engine gate.
        /// </summary>
        private void EnsureWritable()
        {
            if (_readOnly)
                throw new UnauthorizedAccessException("SFTP server is read-only.");
        }

        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes)
        {
            var absPath = GetAbsolutePath(path);

            var access = default(FileAccess);
            if ((flags & SftpOpenFlags.Read) != 0) access |= FileAccess.Read;
            if ((flags & SftpOpenFlags.Write) != 0) access |= FileAccess.Write;
            if (access == default)
                throw new ArgumentException("No SSH_FXF_READ or SSH_FXF_WRITE specified.", nameof(flags));

            if ((flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create |
                          SftpOpenFlags.Truncate | SftpOpenFlags.Exclusive)) != 0)
                EnsureWritable();

            var mode = MapMode(flags);
            var append = (flags & SftpOpenFlags.Append) != 0;
            var fs = new FileStream(absPath, mode, access);
            return new LocalFileHandle(fs, absPath, append, _readOnly);
        }

        public ISftpDirectoryHandle OpenDirectory(string path)
        {
            var absPath = GetAbsolutePath(path);
            if (!Directory.Exists(absPath))
                throw new DirectoryNotFoundException(absPath);
            if (!HasReadPermission(absPath))
                throw new UnauthorizedAccessException(absPath);

            return new LocalDirectoryHandle(absPath);
        }

        public SftpFileAttributes GetAttributes(string path, bool followLinks)
        {
            var absPath = GetAbsolutePath(path);
            if (followLinks)
            {
                if (File.Exists(absPath) || Directory.Exists(absPath))
                    return GetAttr(new FileInfo(absPath));
                throw new FileNotFoundException(null, absPath);
            }

            // LSTAT: report the link itself, not its target. .NET exposes
            // links via FileSystemInfo.LinkTarget; when the path is a link,
            // FileInfo/DirectoryInfo already describe the link entry.
            var info = GetInfo(absPath);
            return GetAttr(info);
        }

        public void SetAttributes(string path, SftpFileAttributes attributes)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path);
            var info = GetInfo(absPath);
            ApplyAttr(info, attributes);
        }

        public void RemoveFile(string path)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path);
            if (Directory.Exists(absPath))
                throw new UnauthorizedAccessException($"'{path}' is a directory; use RMDIR.");
            File.Delete(absPath);
        }

        public void Rename(string oldPath, string newPath)
        {
            EnsureWritable();
            var absOld = GetAbsolutePath(oldPath);
            var absNew = GetAbsolutePath(newPath);
            if (File.GetAttributes(absOld).HasFlag(FileAttributes.Directory))
                Directory.Move(absOld, absNew);
            else
                File.Move(absOld, absNew);
        }

        public void MakeDirectory(string path, SftpFileAttributes attributes)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path);
            if (Directory.Exists(absPath) || File.Exists(absPath))
                throw new IOException($"'{path}' already exists.");
            Directory.CreateDirectory(absPath);
            if (attributes != null)
                ApplyAttr(new DirectoryInfo(absPath), attributes);
        }

        public void RemoveDirectory(string path)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path);
            if (!Directory.Exists(absPath))
                throw new DirectoryNotFoundException(absPath);
            Directory.Delete(absPath, false);
        }

        public string RealPath(string path)
        {
            // Canonical absolute form: resolve against the root, then expose
            // it as a "/"-rooted path within the jail (section 6.11). The
            // root itself canonicalizes to "/", not "/." (GetRelativePath
            // returns "." for the base path).
            var absPath = GetAbsolutePath(path);
            if (string.Equals(absPath, _rootPath, StringComparison.Ordinal))
                return "/";

            var relative = Path.GetRelativePath(_rootPath, absPath)
                .Replace(Path.DirectorySeparatorChar, '/');
            return "/" + relative;
        }

        private FileMode MapMode(SftpOpenFlags flags)
        {
            var create = (flags & SftpOpenFlags.Create) != 0;
            var trunc = (flags & SftpOpenFlags.Truncate) != 0;
            var excl = (flags & SftpOpenFlags.Exclusive) != 0;

            if (!create && (trunc || excl))
                throw new ArgumentException("SSH_FXF_TRUNC and SSH_FXF_EXCL require SSH_FXF_CREAT.", nameof(flags));

            if (create)
            {
                if (excl) return FileMode.CreateNew;
                // CREAT|TRUNC must create-or-truncate (put semantics): the
                // file may not exist yet, so FileMode.Truncate (which
                // requires an existing file) would throw.
                if (trunc) return FileMode.Create;
                return FileMode.OpenOrCreate;
            }

            return FileMode.Open;
        }

        /// <summary>
        /// Resolve a client path against the root and verify it cannot escape
        /// the jail. Throws <see cref="UnauthorizedAccessException"/> on
        /// traversal attempts (section 6.2 security warning).
        /// </summary>
        private string GetAbsolutePath(string path)
        {
            var trimmed = path?.TrimStart('/') ?? string.Empty;

            // Draft 6.2: an empty path refers to the user's default
            // directory, which in a chroot is the root itself. "~" is the
            // shell convention clients (WinSCP, FileZilla) send in REALPATH
            // to probe the starting directory; map it to the root as well.
            if (trimmed.Length == 0 || trimmed == "~" || trimmed == "~/")
                return _rootPath;

            var absPath = Path.GetFullPath(Path.Combine(_rootPath, trimmed));
            if (!IsWithinRoot(_rootPath, absPath))
                throw new UnauthorizedAccessException($"Path '{path}' escapes the SFTP root.");
            return absPath;
        }

        /// <summary>
        /// True when <paramref name="path"/> is the jail root or inside it.
        /// <paramref name="root"/> is normalized with a trailing separator,
        /// while GetFullPath results drop it (except on the filesystem root
        /// itself), so compare on trimmed forms.
        /// </summary>
        private static bool IsWithinRoot(string root, string path)
        {
            var rootTrimmed = root.TrimEnd(Path.DirectorySeparatorChar);
            if (rootTrimmed.Length == 0)
                return true; // jail is the filesystem root: everything is inside
            return string.Equals(path, rootTrimmed, StringComparison.Ordinal)
                || path.StartsWith(rootTrimmed + Path.DirectorySeparatorChar, StringComparison.Ordinal);
        }

        private bool HasReadPermission(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    using (File.Open(path, FileMode.Open, FileAccess.Read))
                        return true;
                }
                if (Directory.Exists(path))
                {
                    new DirectoryInfo(path).GetFileSystemInfos();
                    return true;
                }
            }
            catch
            {
            }
            return false;
        }

        private static FileSystemInfo GetInfo(string absPath)
        {
            var attributes = File.GetAttributes(absPath);
            return attributes.HasFlag(FileAttributes.Directory)
                ? new DirectoryInfo(absPath)
                : new FileInfo(absPath);
        }

        private static SftpFileAttributes GetAttr(FileSystemInfo info)
        {
            try
            {
                var isDir = info.Attributes.HasFlag(FileAttributes.Directory);
                var attr = new SftpFileAttributes
                {
                    // 0x4000 is directory, 0x8000 is regular file; 0x01B6 equals 0o666.
                    Permissions = isDir ? 0x41B6u : 0x81B6u,
                    AccessTime = (uint)new DateTimeOffset(info.LastAccessTimeUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
                    ModificationTime = (uint)new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
                };
                if (!isDir)
                    attr.Size = (ulong)new FileInfo(info.FullName).Length;
                return attr;
            }
            catch
            {
                return null;
            }
        }

        private static void ApplyAttr(FileSystemInfo info, SftpFileAttributes attr)
        {
            if (attr == null)
                return;
            if (attr.AccessTime != null)
                info.LastAccessTimeUtc = DateTimeOffset.FromUnixTimeSeconds(attr.AccessTime.Value).UtcDateTime;
            if (attr.ModificationTime != null)
                info.LastWriteTimeUtc = DateTimeOffset.FromUnixTimeSeconds(attr.ModificationTime.Value).UtcDateTime;
            if (attr.Size != null && info is FileInfo file)
            {
                // Truncate/extend the file to the requested size (section 6.9).
                using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write);
                fs.SetLength((long)attr.Size.Value);
            }
        }

        private sealed class LocalFileHandle : ISftpFileHandle
        {
            private readonly FileStream _fs;
            private readonly bool _append;
            private readonly bool _readOnly;

            public LocalFileHandle(FileStream fs, string path, bool append, bool readOnly)
            {
                _fs = fs;
                _append = append;
                _readOnly = readOnly;
            }

            public int Read(long offset, Span<byte> buffer)
            {
                _fs.Position = offset;
                return _fs.Read(buffer);
            }

            public void Write(long offset, ReadOnlySpan<byte> data)
            {
                if (_readOnly)
                    throw new UnauthorizedAccessException("SFTP server is read-only.");

                // SSH_FXF_APPEND forces writes to the end regardless of offset.
                _fs.Position = _append ? _fs.Length : offset;
                _fs.Write(data);
            }

            public SftpFileAttributes GetAttributes() => GetAttr(new FileInfo(_fs.Name));

            public void SetAttributes(SftpFileAttributes attributes)
            {
                if (_readOnly)
                    throw new UnauthorizedAccessException("SFTP server is read-only.");

                if (attributes?.Size != null)
                    _fs.SetLength((long)attributes.Size.Value);
                ApplyAttr(new FileInfo(_fs.Name), attributes);
            }

            public void Dispose() => _fs.Dispose();
        }

        private sealed class LocalDirectoryHandle : ISftpDirectoryHandle
        {
            private readonly FileSystemInfo[] _entries;
            private int _cursor;

            public LocalDirectoryHandle(string absPath)
            {
                _entries = new DirectoryInfo(absPath).GetFileSystemInfos();
            }

            public SftpFileEntry[] ReadEntries(int maxCount)
            {
                if (_cursor >= _entries.Length)
                    return Array.Empty<SftpFileEntry>();

                var count = Math.Min(maxCount, _entries.Length - _cursor);
                var result = new SftpFileEntry[count];
                for (var i = 0; i < count; i++)
                {
                    var info = _entries[_cursor + i];
                    result[i] = new SftpFileEntry
                    {
                        FileName = info.Name,
                        Attributes = GetAttr(info),
                    };
                }
                _cursor += count;
                return result;
            }

            public void Dispose()
            {
            }
        }
    }
}
