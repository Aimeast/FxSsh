using System;
using System.Collections.Generic;
using System.IO;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// Default <see cref="ISftpFileSystem"/> backed by the local disk, rooted
    /// at a single directory (a chroot-style jail). All client paths are
    /// resolved against the configured root directory and are prevented from
    /// escaping it (draft-ietf-secsh-filexfer-02, section 6.2), including
    /// through symbolic links and NTFS junctions inside the jail: every path
    /// component is resolved and a link that points outside the root is
    /// rejected.
    ///
    /// Errors surface as the corresponding .NET exceptions; the protocol
    /// engine maps them to SSH_FX_* status codes. This is the one place
    /// platform-specific path handling lives.
    /// </summary>
    /// <remarks>
    /// The jail is best-effort, not a security boundary. Path resolution and
    /// the subsequent file operation are separate steps, so a concurrent
    /// local process that can replace a path component can still race the
    /// check between validation and use (TOCTOU). For adversarial local
    /// users, combine this with OS-level isolation (a dedicated service
    /// account, chroot/container, or mount namespace) instead of relying on
    /// the path checks alone.
    /// </remarks>
    public sealed class LocalFileSystem : ISftpFileSystem
    {
        /// <summary>Maximum number of links followed while resolving one path (matches the Linux ELOOP limit).</summary>
        private const int MaximumLinkHops = 40;

        private readonly string _rootPath;
        private readonly bool _readOnly;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalFileSystem"/> class that
        /// serves files from beneath <paramref name="rootPath"/> in read-write mode.
        /// </summary>
        /// <param name="rootPath">Directory that becomes the visible SFTP root ("/").</param>
        public LocalFileSystem(string rootPath)
            : this(rootPath, readOnly: false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalFileSystem"/> class that
        /// serves files from beneath <paramref name="rootPath"/>.
        /// </summary>
        /// <param name="rootPath">Directory that becomes the visible SFTP root ("/").</param>
        /// <param name="readOnly">True to make every mutating operation throw <see cref="UnauthorizedAccessException"/>.</param>
        public LocalFileSystem(string rootPath, bool readOnly)
        {
            ArgumentNullException.ThrowIfNull(rootPath);

            // Resolve links in the root itself (e.g. /tmp -> /private/tmp):
            // the jail must be checked against the real directory, otherwise
            // every resolved link target would look like an escape.
            var realRoot = ResolveRootLinks(Path.GetFullPath(rootPath));

            // Normalize once: ensure a trailing separator so the escape check
            // ("starts with root") cannot be fooled by prefix siblings.
            var trimmed = Path.TrimEndingDirectorySeparator(realRoot);
            _rootPath = trimmed.EndsWith(Path.DirectorySeparatorChar)
                ? trimmed
                : trimmed + Path.DirectorySeparatorChar;
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

        /// <summary>
        /// Opens (or creates) the file at <paramref name="path"/> and returns a
        /// positional handle over it. Maps to SSH_FXP_OPEN.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <param name="flags">Open mode flags (SSH_FXF_*); at least one of <see cref="SftpOpenFlags.Read"/> or <see cref="SftpOpenFlags.Write"/> must be set.</param>
        /// <param name="attributes">Initial attributes for a created file; may be null.</param>
        /// <returns>A handle for positional reads and writes on the file.</returns>
        /// <exception cref="ArgumentException">No access flag was requested, or <see cref="SftpOpenFlags.Truncate"/> or <see cref="SftpOpenFlags.Exclusive"/> was set without <see cref="SftpOpenFlags.Create"/>.</exception>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root (including through a link), the file system is read-only and a write-capable flag was set, or the OS denied access.</exception>
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

            // OPEN may carry the initial mode/times for a file it creates
            // (draft section 6.3). As with open(2), they only apply when the
            // file did not exist, so a plain OPEN cannot chmod an existing
            // file; without this a client asking for 0600 would get the
            // umask-derived default instead.
            var existed = File.Exists(absPath);

            // Share write/delete so a FSETSTAT (or a second SFTP open) can
            // open the file again while this handle is alive - without this,
            // Windows fails the second open with "used by another process".
            var fs = new FileStream(absPath, mode, access, FileShare.Read | FileShare.Write | FileShare.Delete);
            if (!existed && (flags & SftpOpenFlags.Create) != 0 && attributes != null)
            {
                try
                {
                    ApplyAttr(new FileInfo(absPath), attributes);
                }
                catch
                {
                    // Do not leave a half-configured handle behind.
                    fs.Dispose();
                    throw;
                }
            }

            return new LocalFileHandle(fs, absPath, append, _readOnly);
        }

        /// <summary>
        /// Opens the directory at <paramref name="path"/> for listing. Maps to
        /// SSH_FXP_OPENDIR.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <returns>A handle that streams the directory's entries in batches.</returns>
        /// <exception cref="DirectoryNotFoundException">The path does not exist or is not a directory.</exception>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root or cannot be read.</exception>
        public ISftpDirectoryHandle OpenDirectory(string path)
        {
            var absPath = GetAbsolutePath(path);
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(absPath);
            }
            catch (FileNotFoundException)
            {
                throw new DirectoryNotFoundException(absPath);
            }

            if ((attributes & FileAttributes.Directory) == 0)
                throw new DirectoryNotFoundException(absPath);

            return new LocalDirectoryHandle(absPath);
        }

        /// <summary>
        /// Retrieves the attributes of <paramref name="path"/>. Maps to SSH_FXP_STAT
        /// when <paramref name="followLinks"/> is true, SSH_FXP_LSTAT otherwise.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <param name="followLinks">True to follow symbolic links; false to report a link itself.</param>
        /// <returns>The file's attributes, or null when they cannot be read.</returns>
        /// <exception cref="FileNotFoundException">The path does not exist.</exception>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root.</exception>
        public SftpFileAttributes GetAttributes(string path, bool followLinks)
        {
            var absPath = GetAbsolutePath(path, followLinks);
            try
            {
                // GetInfo lets permission/IO failures propagate as their real
                // exception type; File.Exists/Directory.Exists would swallow
                // them and misreport the file as missing.
                return GetAttr(GetInfo(absPath));
            }
            catch (FileNotFoundException)
            {
                throw new FileNotFoundException($"File not found: {absPath}", absPath);
            }
            catch (DirectoryNotFoundException)
            {
                throw new FileNotFoundException($"File not found: {absPath}", absPath);
            }
        }

        /// <summary>
        /// Applies the times and size carried by <paramref name="attributes"/> to the
        /// file at <paramref name="path"/>; a non-null size truncates or extends the
        /// file, and POSIX permissions are applied on Unix. Maps to SSH_FXP_SETSTAT.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <param name="attributes">Attributes to apply; null fields are left unchanged.</param>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root or the file system is read-only.</exception>
        public void SetAttributes(string path, SftpFileAttributes attributes)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path);
            var info = GetInfo(absPath);
            ApplyAttr(info, attributes);
        }

        /// <summary>
        /// Deletes the file at <paramref name="path"/>. A symbolic link is
        /// removed itself, never its target. Maps to SSH_FXP_REMOVE.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <exception cref="UnauthorizedAccessException">The path is a directory, escapes the root, or the file system is read-only.</exception>
        public void RemoveFile(string path)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path, followFinalLink: false);
            var fileAttributes = File.GetAttributes(absPath);
            if ((fileAttributes & FileAttributes.Directory) != 0)
            {
                // A link to a directory is removed as a link; a real
                // directory must go through RMDIR.
                if ((fileAttributes & FileAttributes.ReparsePoint) == 0)
                    throw new UnauthorizedAccessException($"'{path}' is a directory; use RMDIR.");
                Directory.Delete(absPath, recursive: false);
                return;
            }

            File.Delete(absPath);
        }

        /// <summary>
        /// Moves the file or directory at <paramref name="oldPath"/> to
        /// <paramref name="newPath"/>. Maps to SSH_FXP_RENAME.
        /// </summary>
        /// <param name="oldPath">Server-side source path, resolved against the root.</param>
        /// <param name="newPath">Server-side destination path, resolved against the root.</param>
        /// <exception cref="UnauthorizedAccessException">Either path escapes the root or the file system is read-only.</exception>
        public void Rename(string oldPath, string newPath)
        {
            EnsureWritable();
            // Never follow the final components: renaming moves the link
            // entry itself, and a link at the destination is replaced rather
            // than written through. Intermediate directories are still
            // resolved and kept inside the jail.
            var absOld = GetAbsolutePath(oldPath, followFinalLink: false);
            var absNew = GetAbsolutePath(newPath, followFinalLink: false);
            var fileAttributes = File.GetAttributes(absOld);
            if ((fileAttributes & FileAttributes.Directory) != 0 &&
                (fileAttributes & FileAttributes.ReparsePoint) == 0)
                Directory.Move(absOld, absNew);
            else
                File.Move(absOld, absNew);
        }

        /// <summary>
        /// Creates the directory at <paramref name="path"/>, optionally applying
        /// <paramref name="attributes"/> to it. Maps to SSH_FXP_MKDIR.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <param name="attributes">Attributes to apply to the new directory; may be null.</param>
        /// <exception cref="DirectoryNotFoundException">The parent directory does not exist.</exception>
        /// <exception cref="IOException">A file or directory already exists at the path.</exception>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root or the file system is read-only.</exception>
        public void MakeDirectory(string path, SftpFileAttributes attributes)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path, followFinalLink: false);
            if (TryGetAttributes(absPath, out _))
                throw new IOException($"'{path}' already exists.");

            // MKDIR is single-level: unlike Directory.CreateDirectory, a
            // missing parent must fail (draft 6.5), not be created silently.
            var parent = Path.GetDirectoryName(absPath);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
                throw new DirectoryNotFoundException($"Parent directory not found for '{path}'.");

            Directory.CreateDirectory(absPath);
            if (attributes != null)
                ApplyAttr(new DirectoryInfo(absPath), attributes);
        }

        /// <summary>
        /// Deletes the empty directory at <paramref name="path"/>. The final
        /// link is not followed, so a link is removed instead of its target
        /// being deleted. Maps to SSH_FXP_RMDIR.
        /// </summary>
        /// <param name="path">Server-side path, resolved against the root.</param>
        /// <exception cref="DirectoryNotFoundException">The path does not exist.</exception>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root or the file system is read-only.</exception>
        public void RemoveDirectory(string path)
        {
            EnsureWritable();
            var absPath = GetAbsolutePath(path, followFinalLink: false);
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(absPath);
            }
            catch (FileNotFoundException)
            {
                throw new DirectoryNotFoundException(absPath);
            }

            if ((attributes & FileAttributes.Directory) == 0)
                throw new DirectoryNotFoundException(absPath);
            Directory.Delete(absPath, recursive: false);
        }

        /// <summary>
        /// Resolves <paramref name="path"/> to its canonical absolute form inside the
        /// jail, using '/' separators; the root itself canonicalizes to "/". Maps to
        /// SSH_FXP_REALPATH.
        /// </summary>
        /// <param name="path">Server-side path; an empty path or "~" refers to the root.</param>
        /// <returns>The canonical absolute path.</returns>
        /// <exception cref="UnauthorizedAccessException">The path escapes the root.</exception>
        public string RealPath(string path)
        {
            // Canonical absolute form: resolve against the root, then expose
            // it as a "/"-rooted path within the jail (section 6.11). The
            // root itself canonicalizes to "/", not "/." (GetRelativePath
            // returns "." for the base path).
            var absPath = GetAbsolutePath(path);
            if (IsSamePath(absPath, _rootPath))
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
        /// <param name="path">Client path.</param>
        /// <param name="followFinalLink">
        /// True to resolve a link in the final component (open/stat target);
        /// false for operations that act on the link entry itself (LSTAT,
        /// REMOVE, RENAME, RMDIR).
        /// </param>
        private string GetAbsolutePath(string path, bool followFinalLink = true)
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

            var relative = Path.GetRelativePath(_rootPath, absPath);
            if (relative == ".")
                return _rootPath;

            return ResolveComponents(relative, followFinalLink);
        }

        /// <summary>
        /// Walk the components of <paramref name="relativePath"/>, resolving
        /// every symbolic link / junction and verifying that its target stays
        /// inside the jail. This closes the lexical-only check: a link such
        /// as "docs" pointing at a directory outside the root would otherwise
        /// let every operation on "/docs/..." reach outside the jail.
        /// </summary>
        private string ResolveComponents(string relativePath, bool followFinalLink)
        {
            var current = _rootPath;
            var remaining = relativePath;
            var budget = MaximumLinkHops;

            while (true)
            {
                remaining = remaining.TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (remaining.Length == 0)
                    return Path.TrimEndingDirectorySeparator(current);

                var separator = remaining.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]);
                string part;
                if (separator < 0)
                {
                    part = remaining;
                    remaining = string.Empty;
                }
                else
                {
                    part = remaining[..separator];
                    remaining = remaining[(separator + 1)..];
                }

                if (part.Length == 0 || part == ".")
                    continue;
                if (part == "..")
                    throw new UnauthorizedAccessException($"Path '{relativePath}' escapes the SFTP root.");

                var next = Path.Combine(current, part);
                var isFinal = remaining.Length == 0;

                if (isFinal)
                {
                    if (!followFinalLink)
                        return next;

                    // Follow a link in the final component - this includes
                    // dangling links, which GetLinkTargetOrNull still
                    // reports, so CREAT through a link cannot escape.
                    if (GetLinkTargetOrNull(next, out _) == null)
                        return next;
                    return ResolveLinkChain(next, ref budget);
                }

                var linkTarget = GetLinkTargetOrNull(next, out var exists);
                if (linkTarget == null)
                {
                    if (!exists)
                    {
                        // The component does not exist, so nothing after it
                        // can be a link: compose the remainder lexically and
                        // keep the jail check.
                        var composed = Path.GetFullPath(Path.Combine(next, remaining));
                        if (!IsWithinRoot(_rootPath, composed))
                            throw new UnauthorizedAccessException($"Path '{relativePath}' escapes the SFTP root.");
                        return composed;
                    }

                    current = next;
                    continue;
                }

                // Intermediate link: resolve it, then re-resolve the rest of
                // the path relative to the (verified) target.
                var resolved = ResolveLinkChain(next, ref budget);
                var combined = Path.GetFullPath(Path.Combine(resolved, remaining));
                if (!IsWithinRoot(_rootPath, combined))
                    throw new UnauthorizedAccessException($"Path '{relativePath}' escapes the SFTP root.");

                remaining = Path.GetRelativePath(_rootPath, combined);
                current = _rootPath;
            }
        }

        /// <summary>
        /// Follow the chain of links starting at <paramref name="path"/> and
        /// return the final target. Every hop must stay inside the jail;
        /// a hop outside is an escape, not something to resolve further.
        /// </summary>
        private string ResolveLinkChain(string path, ref int budget)
        {
            var current = path;
            while (true)
            {
                var target = GetLinkTargetOrNull(current, out _);
                if (target == null)
                    return current;

                if (--budget < 0)
                    throw new UnauthorizedAccessException("Too many levels of symbolic links.");

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent))
                    throw new UnauthorizedAccessException($"Cannot resolve symbolic link '{path}'.");

                current = Path.GetFullPath(Path.IsPathRooted(target)
                    ? target
                    : Path.Combine(parent, target));
                if (!IsWithinRoot(_rootPath, current))
                    throw new UnauthorizedAccessException($"Path '{path}' escapes the SFTP root through a symbolic link.");
            }
        }

        /// <summary>
        /// Resolve links in the jail root itself. Unlike path components, the
        /// root is trusted configuration, so no containment check applies.
        /// </summary>
        private static string ResolveRootLinks(string path)
        {
            var current = path;
            for (var hop = 0; hop < MaximumLinkHops; hop++)
            {
                var target = GetLinkTargetOrNull(current, out _);
                if (target == null)
                    return Path.TrimEndingDirectorySeparator(current);

                var parent = Path.GetDirectoryName(current);
                if (string.IsNullOrEmpty(parent))
                    return current;

                current = Path.GetFullPath(Path.IsPathRooted(target)
                    ? target
                    : Path.Combine(parent, target));
            }

            throw new UnauthorizedAccessException("Too many levels of symbolic links in the SFTP root.");
        }

        /// <summary>
        /// Return the target of the link entry at <paramref name="path"/>, or
        /// null when the path is not a link. Reads the entry itself (lstat
        /// semantics), so a dangling link is still reported.
        /// <paramref name="exists"/> reports whether the entry itself exists,
        /// so callers can distinguish "regular file" from "missing path"
        /// without a second metadata syscall.
        /// </summary>
        /// <exception cref="UnauthorizedAccessException">The path is a reparse point whose target cannot be verified.</exception>
        private static string GetLinkTargetOrNull(string path, out bool exists)
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(path);
                exists = true;
            }
            catch (FileNotFoundException)
            {
                attributes = default;
                exists = false;
            }
            catch (DirectoryNotFoundException)
            {
                attributes = default;
                exists = false;
            }

            if (attributes != default)
            {
                if ((attributes & FileAttributes.ReparsePoint) == 0)
                    return null;

                FileSystemInfo info = (attributes & FileAttributes.Directory) != 0
                    ? new DirectoryInfo(path)
                    : new FileInfo(path);
                var target = info.LinkTarget;
                if (target == null)
                {
                    // Some reparse-point kinds (cloud placeholders, mount
                    // points) have no readable target. Fail closed rather
                    // than treat them as regular files.
                    info = info is DirectoryInfo ? new FileInfo(path) : new DirectoryInfo(path);
                    target = info.LinkTarget;
                }

                if (string.IsNullOrEmpty(target))
                    throw new UnauthorizedAccessException($"Cannot verify the target of link '{path}'.");
                return target;
            }

            // The path (or a dangling link entry) is invisible to
            // GetAttributes. LinkTarget reads the entry directly and reports
            // a dangling link's target, which is exactly what must be
            // checked before a CREAT follows it.
            return new FileInfo(path).LinkTarget ?? new DirectoryInfo(path).LinkTarget;
        }

        private static bool TryGetAttributes(string path, out FileAttributes attributes)
        {
            try
            {
                attributes = File.GetAttributes(path);
                return true;
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }

            attributes = default;
            return false;
        }

        /// <summary>
        /// True when <paramref name="path"/> is the jail root or inside it.
        /// <paramref name="root"/> is normalized with a trailing separator,
        /// while GetFullPath results drop it (except on the filesystem root
        /// itself), so compare on trimmed forms.
        /// </summary>
        private static bool IsWithinRoot(string root, string path)
        {
            // Windows paths are case-insensitive; comparing ordinally would
            // both reject valid paths and weaken the check.
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            var rootTrimmed = Path.TrimEndingDirectorySeparator(root);
            if (rootTrimmed.Length == 0)
                return true;

            if (string.Equals(Path.TrimEndingDirectorySeparator(path), rootTrimmed, comparison))
                return true;

            // Filesystem root ("/" or "C:\"): everything on it is inside.
            if (rootTrimmed.EndsWith(Path.DirectorySeparatorChar))
                return path.StartsWith(rootTrimmed, comparison);

            return path.StartsWith(rootTrimmed + Path.DirectorySeparatorChar, comparison);
        }

        private static bool IsSamePath(string left, string right)
        {
            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            return string.Equals(
                Path.TrimEndingDirectorySeparator(left),
                Path.TrimEndingDirectorySeparator(right),
                comparison);
        }

        private static FileSystemInfo GetInfo(string absPath)
        {
            var attributes = File.GetAttributes(absPath);
            return (attributes & FileAttributes.Directory) != 0
                ? new DirectoryInfo(absPath)
                : new FileInfo(absPath);
        }

        private static SftpFileAttributes GetAttr(FileSystemInfo info)
        {
            var fileAttributes = info.Attributes;
            var isLink = (fileAttributes & FileAttributes.ReparsePoint) != 0;
            var isDir = (fileAttributes & FileAttributes.Directory) != 0;

            var attr = new SftpFileAttributes
            {
                Permissions = GetPermissions(info, isDir, isLink),
                AccessTime = (uint)new DateTimeOffset(info.LastAccessTimeUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
                ModificationTime = (uint)new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
            };

            // Never follow a link while filling attributes (LSTAT
            // semantics; a dangling link has no target to measure).
            if (!isDir && !isLink && info is FileInfo file)
                attr.Size = (ulong)file.Length;
            return attr;
        }

        /// <summary>
        /// Report the POSIX type + permission bits. On Unix the real mode is
        /// read from the entry; links report the conventional 0777 because
        /// their own mode is not exposed. Windows has no POSIX mode, so a
        /// conventional 0755/0644 is reported.
        /// </summary>
        private static uint GetPermissions(FileSystemInfo info, bool isDir, bool isLink)
        {
            if (isLink)
                return 0xA1FFu; // 0xA000 | 0777
            if (OperatingSystem.IsWindows())
                return isDir ? 0x41EDu : 0x81A4u; // 0x4000/0x8000 | 0755/0644

            var mode = (uint)File.GetUnixFileMode(info.FullName) & 0x1FFu;
            return (isDir ? 0x4000u : 0x8000u) | mode;
        }

        private static void ApplyAttr(FileSystemInfo info, SftpFileAttributes attr)
        {
            if (attr == null)
                return;

            if (attr.Permissions is { } permissions && !OperatingSystem.IsWindows())
            {
                // Only apply the low nine permission bits; the file type in
                // the high bits is informational and cannot be changed.
                var type = permissions & 0xF000u;
                if (type == 0 || type == 0x4000u || type == 0x8000u)
                    File.SetUnixFileMode(info.FullName, (UnixFileMode)(permissions & 0x1FFu));
            }

            if (attr.Size != null && info is FileInfo file)
            {
                // Truncate/extend the file to the requested size (section 6.9).
                // Share-friendly: the caller may hold an open SFTP handle on
                // the same file (scp's post-upload FSETSTAT does exactly this).
                using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Write, FileShare.Read | FileShare.Write | FileShare.Delete);
                fs.SetLength((long)attr.Size.Value);
            }

            // Times last: truncation and chmod above would otherwise update
            // the timestamps the client asked for.
            if (attr.AccessTime != null)
                info.LastAccessTimeUtc = DateTimeOffset.FromUnixTimeSeconds(attr.AccessTime.Value).UtcDateTime;
            if (attr.ModificationTime != null)
                info.LastWriteTimeUtc = DateTimeOffset.FromUnixTimeSeconds(attr.ModificationTime.Value).UtcDateTime;
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

        /// <summary>
        /// Lazily enumerates the directory: entries are pulled on demand in
        /// READDIR-sized batches instead of materializing the whole listing,
        /// so a huge directory cannot exhaust memory on OPENDIR.
        /// </summary>
        private sealed class LocalDirectoryHandle : ISftpDirectoryHandle
        {
            private readonly IEnumerator<FileSystemInfo> _enumerator;
            private bool _finished;

            public LocalDirectoryHandle(string absPath)
            {
                _enumerator = new DirectoryInfo(absPath).EnumerateFileSystemInfos().GetEnumerator();
            }

            public SftpFileEntry[] ReadEntries(int maxCount)
            {
                if (maxCount <= 0 || _finished)
                    return Array.Empty<SftpFileEntry>();

                var result = new List<SftpFileEntry>(Math.Min(maxCount, 256));
                while (result.Count < maxCount)
                {
                    if (!_enumerator.MoveNext())
                    {
                        _finished = true;
                        break;
                    }

                    var info = _enumerator.Current;
                    result.Add(new SftpFileEntry
                    {
                        FileName = info.Name,
                        Attributes = GetAttr(info),
                    });
                }

                return result.ToArray();
            }

            public void Dispose() => _enumerator.Dispose();
        }
    }
}
