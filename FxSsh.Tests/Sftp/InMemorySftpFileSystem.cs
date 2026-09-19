using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FxSsh.Services.Sftp;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// In-memory <see cref="ISftpFileSystem"/> for driving the SFTP protocol
    /// engine without disk I/O. Records every backend call so tests can
    /// assert delegation and read-only gating.
    /// </summary>
    internal sealed class InMemorySftpFileSystem : ISftpFileSystem
    {
        public sealed class MemoryFileHandle : ISftpFileHandle
        {
            private readonly Dictionary<string, byte[]> _files;
            private readonly string _path;
            private byte[] _data;

            public MemoryFileHandle(Dictionary<string, byte[]> files, string path, byte[] initial)
            {
                _files = files;
                _path = path;
                _data = initial;
            }

            public bool Disposed { get; private set; }

            public byte[] Data => _data;

            public int Read(long offset, Span<byte> buffer)
            {
                if (offset >= _data.Length)
                    return 0;

                var count = Math.Min(buffer.Length, _data.Length - (int)offset);
                _data.AsSpan((int)offset, count).CopyTo(buffer);
                return count;
            }

            public void Write(long offset, ReadOnlySpan<byte> data)
            {
                var end = (int)offset + data.Length;
                if (end > _data.Length)
                {
                    Array.Resize(ref _data, end);
                    _files[_path] = _data; // the resized array replaces the stored one
                }

                data.CopyTo(_data.AsSpan((int)offset));
            }

            public SftpFileAttributes GetAttributes() => new()
            {
                Size = (ulong)_data.Length,
                Permissions = 0x81B6,
            };

            public void SetAttributes(SftpFileAttributes attributes)
            {
                if (attributes?.Size != null)
                {
                    Array.Resize(ref _data, (int)attributes.Size.Value);
                    _files[_path] = _data;
                }
            }

            public void Dispose() => Disposed = true;
        }

        private sealed class MemoryDirectoryHandle : ISftpDirectoryHandle
        {
            private readonly SftpFileEntry[] _entries;
            private int _cursor;

            public MemoryDirectoryHandle(SftpFileEntry[] entries)
            {
                _entries = entries;
            }

            public SftpFileEntry[] ReadEntries(int maxCount)
            {
                if (_cursor >= _entries.Length)
                    return Array.Empty<SftpFileEntry>();

                var count = Math.Min(maxCount, _entries.Length - _cursor);
                var result = new SftpFileEntry[count];
                Array.Copy(_entries, _cursor, result, 0, count);
                _cursor += count;
                return result;
            }

            public void Dispose()
            {
            }
        }

        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Directories { get; } = new(StringComparer.Ordinal);

        public List<string> OpenPaths { get; } = [];
        public int SetAttributesCalls { get; private set; }
        public List<string> RemovedFiles { get; } = [];
        public List<(string Old, string New)> Renames { get; } = [];
        public List<string> CreatedDirectories { get; } = [];
        public List<string> RemovedDirectories { get; } = [];
        public MemoryFileHandle? LastFileHandle { get; private set; }

        /// <summary>When set, every backend call throws this exception.</summary>
        public Exception? Fault { get; set; }

        private void FaultIfConfigured()
        {
            if (Fault != null)
                throw Fault;
        }

        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes)
        {
            FaultIfConfigured();
            OpenPaths.Add(path);

            var created = false;
            if ((flags & SftpOpenFlags.Create) != 0 && !Files.ContainsKey(path))
            {
                Files[path] = Array.Empty<byte>();
                created = true;
            }

            if ((flags & SftpOpenFlags.Exclusive) != 0 && !created && Files.ContainsKey(path))
                throw new IOException($"'{path}' already exists.");

            if ((flags & SftpOpenFlags.Truncate) != 0)
                Files[path] = Array.Empty<byte>();

            LastFileHandle = new MemoryFileHandle(Files, path, Files.TryGetValue(path, out var data) ? data : Array.Empty<byte>());
            return LastFileHandle;
        }

        public ISftpDirectoryHandle OpenDirectory(string path)
        {
            FaultIfConfigured();
            if (!Directories.Contains(path))
                throw new DirectoryNotFoundException(path);

            var prefix = path == "/" ? "/" : path + "/";
            var entries = Files.Keys
                .Where(f => f.StartsWith(prefix, StringComparison.Ordinal) && !f[prefix.Length..].Contains('/'))
                .Select(f => new SftpFileEntry
                {
                    FileName = f[prefix.Length..],
                    Attributes = new SftpFileAttributes { Size = (ulong)Files[f].Length, Permissions = 0x81B6 },
                })
                .Concat(Directories
                    .Where(d => d != "/" && d.StartsWith(prefix, StringComparison.Ordinal) && !d[prefix.Length..].Contains('/'))
                    .Select(d => new SftpFileEntry { FileName = d[prefix.Length..], Attributes = new SftpFileAttributes { Permissions = 0x41B6 } }))
                .ToArray();

            return new MemoryDirectoryHandle(entries);
        }

        public SftpFileAttributes GetAttributes(string path, bool followLinks)
        {
            FaultIfConfigured();
            if (Files.TryGetValue(path, out var data))
                return new SftpFileAttributes { Size = (ulong)data.Length, Permissions = 0x81B6 };
            if (Directories.Contains(path))
                return new SftpFileAttributes { Permissions = 0x41B6 };

            throw new FileNotFoundException(null, path);
        }

        public void SetAttributes(string path, SftpFileAttributes attributes)
        {
            FaultIfConfigured();
            SetAttributesCalls++;
        }

        public void RemoveFile(string path)
        {
            FaultIfConfigured();
            RemovedFiles.Add(path);
            Files.Remove(path);
        }

        public void Rename(string oldPath, string newPath)
        {
            FaultIfConfigured();
            Renames.Add((oldPath, newPath));
            if (Files.Remove(oldPath, out var data))
                Files[newPath] = data;
        }

        public void MakeDirectory(string path, SftpFileAttributes attributes)
        {
            FaultIfConfigured();
            CreatedDirectories.Add(path);
            Directories.Add(path);
        }

        public void RemoveDirectory(string path)
        {
            FaultIfConfigured();
            RemovedDirectories.Add(path);
            Directories.Remove(path);
        }

        public string RealPath(string path)
        {
            FaultIfConfigured();
            return path.Length == 0 || path == "~" ? "/" : path.TrimEnd('/');
        }
    }

    /// <summary>A backend whose every operation throws the configured exception.</summary>
    internal sealed class FaultyFileSystem : ISftpFileSystem
    {
        private readonly Exception _exception;

        public FaultyFileSystem(Exception exception)
        {
            _exception = exception;
        }

        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes) => throw _exception;

        public ISftpDirectoryHandle OpenDirectory(string path) => throw _exception;

        public SftpFileAttributes GetAttributes(string path, bool followLinks) => throw _exception;

        public void SetAttributes(string path, SftpFileAttributes attributes) => throw _exception;

        public void RemoveFile(string path) => throw _exception;

        public void Rename(string oldPath, string newPath) => throw _exception;

        public void MakeDirectory(string path, SftpFileAttributes attributes) => throw _exception;

        public void RemoveDirectory(string path) => throw _exception;

        public string RealPath(string path) => throw _exception;
    }
}
