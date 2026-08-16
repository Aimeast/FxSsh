using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FxSsh.Logging;

namespace FxSsh.Services.Sftp
{
    /// <summary>
    /// SFTP protocol engine (draft-ietf-secsh-filexfer-02, version 3),
    /// decoupled from any concrete storage via <see cref="ISftpFileSystem"/>.
    ///
    /// Inbound: feed channel data via <see cref="OnData"/> (frames may span
    /// SSH packets; accumulation and length validation happen here). Outbound:
    /// complete SFTP packets are raised through <see cref="DataReceived"/>,
    /// which <see cref="Attach"/> rewires directly to a channel's SendDataAsync.
    ///
    /// The engine performs no disk I/O: every operation delegates to the
    /// file system abstraction and translates its exceptions into SSH_FX_*
    /// status codes through a single mapping, so a failing backend can never
    /// crash the session.
    /// </summary>
    public sealed class SftpService : IDisposable
    {
        #region Protocol constants (draft-ietf-secsh-filexfer-02)

        // Requests (client -> server).
        private const byte SSH_FXP_INIT = 1;
        private const byte SSH_FXP_VERSION = 2;
        private const byte SSH_FXP_OPEN = 3;
        private const byte SSH_FXP_CLOSE = 4;
        private const byte SSH_FXP_READ = 5;
        private const byte SSH_FXP_WRITE = 6;
        private const byte SSH_FXP_LSTAT = 7;
        private const byte SSH_FXP_FSTAT = 8;
        private const byte SSH_FXP_SETSTAT = 9;
        private const byte SSH_FXP_FSETSTAT = 10;
        private const byte SSH_FXP_OPENDIR = 11;
        private const byte SSH_FXP_READDIR = 12;
        private const byte SSH_FXP_REMOVE = 13;
        private const byte SSH_FXP_MKDIR = 14;
        private const byte SSH_FXP_RMDIR = 15;
        private const byte SSH_FXP_REALPATH = 16;
        private const byte SSH_FXP_STAT = 17;
        private const byte SSH_FXP_RENAME = 18;
        private const byte SSH_FXP_READLINK = 19;
        private const byte SSH_FXP_SYMLINK = 20;
        private const byte SSH_FXP_EXTENDED = 200;

        // Responses (server -> client).
        private const byte SSH_FXP_STATUS = 101;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_DATA = 103;
        private const byte SSH_FXP_NAME = 104;
        private const byte SSH_FXP_ATTRS = 105;

        // Status codes.
        private const uint SSH_FX_OK = 0;
        private const uint SSH_FX_EOF = 1;
        private const uint SSH_FX_NO_SUCH_FILE = 2;
        private const uint SSH_FX_PERMISSION_DENIED = 3;
        private const uint SSH_FX_FAILURE = 4;
        private const uint SSH_FX_BAD_MESSAGE = 5;
        private const uint SSH_FX_OP_UNSUPPORTED = 8;

        /// <summary>Highest SFTP protocol version this engine implements.</summary>
        private const uint SupportedVersion = 3;

        /// <summary>
        /// Upper bound for a single SFTP frame. READ/WRITE payloads are capped
        /// separately (<see cref="MaxReadLength"/>); this guards the frame
        /// parser against a malicious length prefix that would otherwise
        /// allocate unbounded buffers.
        /// </summary>
        private const uint MaxPacketLength = 1 * 1024 * 1024;

        /// <summary>Per-request read cap, aligned with typical SSH channel packet sizes.</summary>
        private const int MaxReadLength = 64 * 1024;

        /// <summary>Entries returned per SSH_FXP_READDIR batch (draft allows one or more).</summary>
        private const int ReadDirBatchSize = 128;

        #endregion

        private readonly ISftpFileSystem _fileSystem;
        private readonly Dictionary<string, HandleEntry> _mapOfHandle = [];
        private readonly CancellationTokenSource _cancellationTokenSource = new();

        private byte[] _pendingBytes;
        private int _handleCursor;

        public SftpService(string rootPath)
            : this(new LocalFileSystem(rootPath), readOnly: false)
        {
        }

        public SftpService(string rootPath, bool readOnly)
            : this(new LocalFileSystem(rootPath), readOnly)
        {
        }

        /// <summary>
        /// Create an engine rooted at the current user's home directory -
        /// the conventional SFTP starting location.
        /// </summary>
        public SftpService()
            : this(LocalFileSystem.FromUserHome(), readOnly: false)
        {
        }

        /// <summary>
        /// Create an engine rooted at the current user's home directory in
        /// read-only mode.
        /// </summary>
        public SftpService(bool readOnly)
            : this(LocalFileSystem.FromUserHome(), readOnly)
        {
        }

        public SftpService(ISftpFileSystem fileSystem)
            : this(fileSystem, readOnly: false)
        {
        }

        public SftpService(ISftpFileSystem fileSystem, bool readOnly)
        {
            ArgumentNullException.ThrowIfNull(fileSystem);
            _fileSystem = fileSystem;
            IsReadOnly = readOnly;
        }

        /// <summary>
        /// True when the server rejects every mutating SFTP request (OPEN with
        /// write flags, WRITE, REMOVE, RENAME, MKDIR, RMDIR, SETSTAT,
        /// FSETSTAT) with SSH_FX_PERMISSION_DENIED. Read operations are
        /// unaffected.
        /// </summary>
        public bool IsReadOnly { get; }

        /// <summary>Complete outbound SFTP packets (length-prefixed frames).</summary>
        public event EventHandler<byte[]> DataReceived;

        /// <summary>Raised when the peer closes the channel; carries an exit code.</summary>
        public event EventHandler<uint> CloseReceived;

        /// <summary>
        /// Wire the engine to a session channel: inbound channel data feeds
        /// <see cref="OnData"/>, outbound packets go back through the channel,
        /// and peer close tears the engine down. One call replaces the manual
        /// event plumbing hosts previously wrote.
        /// </summary>
        public void Attach(SessionChannel channel)
        {
            ArgumentNullException.ThrowIfNull(channel);

            channel.DataReceived += (_, data) => OnData(data);
            channel.EofReceived += (_, _) =>
            {
                // Peer finished sending (RFC 4254 6.2): echo EOF and close
                // our side so the client's bye/close handshake completes
                // instead of hanging.
                channel.SendEof();
                channel.SendClose();
            };
            channel.CloseReceived += (_, _) => OnClose();

            DataReceived += async (_, packet) =>
            {
                // Fire-and-forget with teardown swallowing: after the peer
                // disconnects, SendDataAsync throws ObjectDisposedException,
                // which must not escape onto the thread pool.
                try { await channel.SendDataAsync(packet); }
                catch (ObjectDisposedException) { }
                catch (Exception) { }
            };
            CloseReceived += (_, exitCode) => channel.SendClose(exitCode);
        }

        public void OnData(ReadOnlyMemory<byte> data)
        {
            // The incoming slice is over the SSH receive buffer, which is
            // recycled by the next ReceiveMessage. SFTP frames may span
            // multiple SSH packets (we accumulate into _pendingBytes), so we
            // MUST materialise an independent copy here. This is the one
            // mandatory copy on the SFTP inbound path.
            var bytes = data.ToArray();
            _pendingBytes = _pendingBytes == null ? bytes : [.. _pendingBytes, .. bytes];

            // _pendingBytes is set to null below once a frame is consumed
            // exactly; the loop condition must tolerate that.
            while (_pendingBytes is { Length: >= 4 })
            {
                var reader = new SshDataReader(_pendingBytes);
                var length = reader.ReadUInt32();

                // Frame sanity: length field counts the bytes after itself, so
                // a full frame is length + 4. Reject empty and oversized frames
                // instead of letting a hostile length overflow the parser.
                if (length < 1 || length > MaxPacketLength)
                {
                    Log.Warn($"SFTP: discarding invalid frame length {length}.");
                    _pendingBytes = null;
                    return;
                }

                var frameLength = (int)length + 4;
                if (_pendingBytes.Length < frameLength)
                    return; // wait for the rest of the frame

                // The frame payload starts AFTER the 4-byte length prefix;
                // packet type is payload[0], not the length prefix itself.
                var payload = _pendingBytes.AsMemory(4, (int)length);
                _pendingBytes = _pendingBytes.Length > frameLength
                    ? _pendingBytes[frameLength..]
                    : null;

                ProcessRequest(new SshDataReader(payload));
            }
        }

        public void OnClose()
        {
            _cancellationTokenSource.Cancel();
            CloseAllHandles();
            CloseReceived?.Invoke(this, 0);
        }

        public void WaitForClose()
        {
            Task.Delay(-1, _cancellationTokenSource.Token).Wait();
        }

        /// <summary>Release every open handle (session teardown).</summary>
        public void Dispose()
        {
            CloseAllHandles();
            _cancellationTokenSource.Dispose();
        }

        private void CloseAllHandles()
        {
            lock (_mapOfHandle)
            {
                foreach (var entry in _mapOfHandle.Values)
                    entry.Dispose();
                _mapOfHandle.Clear();
            }
        }

        #region Request dispatch

        private void ProcessRequest(SshDataReader reader)
        {
            var packetType = reader.ReadByte();
            var requestId = 0u;
            try
            {
                // Every request except INIT carries a uint32 request id right
                // after the type byte. Read it here so error responses below
                // can echo the correct id even when a handler throws after
                // consuming all its fields (reader state is then unusable).
                if (packetType != SSH_FXP_INIT)
                    requestId = reader.ReadUInt32();

                switch (packetType)
                {
                    case SSH_FXP_INIT: ProcessInit(reader); break;
                    case SSH_FXP_OPEN: ProcessOpen(reader, requestId); break;
                    case SSH_FXP_CLOSE: ProcessClose(reader, requestId); break;
                    case SSH_FXP_READ: ProcessRead(reader, requestId); break;
                    case SSH_FXP_WRITE: ProcessWrite(reader, requestId); break;
                    case SSH_FXP_LSTAT: ProcessStat(reader, requestId, followLinks: false); break;
                    case SSH_FXP_STAT: ProcessStat(reader, requestId, followLinks: true); break;
                    case SSH_FXP_FSTAT: ProcessFStat(reader, requestId); break;
                    case SSH_FXP_SETSTAT: ProcessSetStat(reader, requestId); break;
                    case SSH_FXP_FSETSTAT: ProcessFSetStat(reader, requestId); break;
                    case SSH_FXP_OPENDIR: ProcessOpenDir(reader, requestId); break;
                    case SSH_FXP_READDIR: ProcessReadDir(reader, requestId); break;
                    case SSH_FXP_REMOVE: ProcessRemove(reader, requestId); break;
                    case SSH_FXP_MKDIR: ProcessMakeDir(reader, requestId); break;
                    case SSH_FXP_RMDIR: ProcessRemoveDir(reader, requestId); break;
                    case SSH_FXP_REALPATH: ProcessRealPath(reader, requestId); break;
                    case SSH_FXP_RENAME: ProcessRename(reader, requestId); break;
                    case SSH_FXP_READLINK:
                    case SSH_FXP_SYMLINK:
                    case SSH_FXP_EXTENDED:
                        // Not implemented: draft section 8 requires the server
                        // to answer unknown/unimplemented operations with
                        // SSH_FX_OP_UNSUPPORTED.
                        SendStatus(requestId, SSH_FX_OP_UNSUPPORTED, "Operation not supported.", "en");
                        break;
                    default:
                        Log.Warn($"SFTP: unknown packet type 0x{packetType:X}.");
                        SendStatus(requestId, SSH_FX_OP_UNSUPPORTED, $"Unknown packet type 0x{packetType:X}.", "en");
                        break;
                }
            }
            catch (Exception ex)
            {
                // Single mapping point: a backend failure becomes a status
                // response, never an exception escaping into the session.
                var (code, message) = MapException(ex);
                Log.Fail($"SFTP request failed (type 0x{packetType:X}, id {requestId}): {ex}");
                SendStatus(requestId, code, message, "en");
            }
        }

        private void ProcessInit(SshDataReader reader)
        {
            // Draft section 4: the server answers with the lowest of its own
            // and the client's version. Any extension data in INIT is
            // silently ignored (mandated for unrecognized extensions).
            var clientVersion = reader.ReadUInt32();
            SendInit(Math.Min(SupportedVersion, clientVersion));
        }

        /// <summary>
        /// Guard for mutating requests in read-only mode: replies
        /// SSH_FX_PERMISSION_DENIED and returns false when writes are
        /// disabled, so callers return without touching the file system.
        /// </summary>
        private bool EnsureWritable(uint requestId)
        {
            if (!IsReadOnly)
                return true;

            SendStatus(requestId, SSH_FX_PERMISSION_DENIED, "Server is read-only.", "en");
            return false;
        }

        private void ProcessOpen(SshDataReader reader, uint requestId)
        {
            var filename = reader.ReadString(Encoding.UTF8);
            var pflags = reader.ReadUInt32();
            var attributes = SftpFileAttributes.Read(reader);

            // Draft 6.3: TRUNC and EXCL are only valid combined with CREAT,
            // and the caller must request at least read or write access.
            var flags = (SftpOpenFlags)pflags;
            if ((flags & (SftpOpenFlags.Read | SftpOpenFlags.Write)) == 0 ||
                (flags & SftpOpenFlags.Truncate) != 0 && (flags & SftpOpenFlags.Create) == 0 ||
                (flags & SftpOpenFlags.Exclusive) != 0 && (flags & SftpOpenFlags.Create) == 0)
            {
                SendStatus(requestId, SSH_FX_BAD_MESSAGE, "Invalid open flags.", "en");
                return;
            }

            // Read-only server: an open that requests any write capability
            // (WRITE/APPEND/CREAT/TRUNC/EXCL) is denied; pure reads pass.
            if ((flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create |
                          SftpOpenFlags.Truncate | SftpOpenFlags.Exclusive)) != 0)
            {
                if (!EnsureWritable(requestId))
                    return;
            }

            var handle = _fileSystem.OpenFile(filename, flags, attributes);
            SendHandle(requestId, RegisterHandle(HandleEntry.ForFile(handle)));
        }

        private void ProcessClose(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry))
                {
                    SendStatus(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en");
                    return;
                }
                _mapOfHandle.Remove(handle);
            }

            // Draft 6.3: close can fail (e.g. flushing cached writes); the
            // failure is reported but the handle is gone either way.
            try { entry.Dispose(); SendStatus(requestId, SSH_FX_OK, "", ""); }
            catch (Exception ex)
            {
                var (code, message) = MapException(ex);
                SendStatus(requestId, code, message, "en");
            }
        }

        private void ProcessRead(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var offset = reader.ReadUInt64();
            var length = reader.ReadUInt32();

            var entry = FindFileHandle(handle, requestId);
            if (entry == null)
                return;

            if (offset > long.MaxValue)
            {
                SendStatus(requestId, SSH_FX_FAILURE, "Offset out of range.", "en");
                return;
            }

            var buffer = new byte[Math.Min(length, (uint)MaxReadLength)];
            var readLength = entry.FileHandle.Read((long)offset, buffer);
            if (readLength > 0)
                SendData(requestId, buffer.AsMemory()[..readLength]);
            else
                SendStatus(requestId, SSH_FX_EOF, "", "");
        }

        private void ProcessWrite(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var offset = reader.ReadUInt64();
            var data = reader.ReadBinary();

            if (!EnsureWritable(requestId))
                return;

            var entry = FindFileHandle(handle, requestId);
            if (entry == null)
                return;

            if (offset > long.MaxValue)
            {
                SendStatus(requestId, SSH_FX_FAILURE, "Offset out of range.", "en");
                return;
            }

            entry.FileHandle.Write((long)offset, data);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessStat(SshDataReader reader, uint requestId, bool followLinks)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var attributes = _fileSystem.GetAttributes(path, followLinks);
            SendAttrs(requestId, attributes);
        }

        private void ProcessFStat(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            // FSTAT never closes the handle (draft 6.8); only CLOSE does.
            var entry = FindFileHandle(handle, requestId);
            if (entry == null)
                return;

            var attributes = entry.FileHandle.GetAttributes();
            SendAttrs(requestId, attributes);
        }

        private void ProcessSetStat(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);
            var attributes = SftpFileAttributes.Read(reader);

            if (!EnsureWritable(requestId))
                return;

            _fileSystem.SetAttributes(path, attributes);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessFSetStat(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);
            var attributes = SftpFileAttributes.Read(reader);

            if (!EnsureWritable(requestId))
                return;

            var entry = FindFileHandle(handle, requestId);
            if (entry == null)
                return;

            entry.FileHandle.SetAttributes(attributes);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessOpenDir(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var handle = _fileSystem.OpenDirectory(path);
            SendHandle(requestId, RegisterHandle(HandleEntry.ForDirectory(handle)));
        }

        private void ProcessReadDir(SshDataReader reader, uint requestId)
        {
            var handle = reader.ReadString(Encoding.ASCII);

            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry) || entry.Kind != HandleKind.Directory)
                {
                    SendStatus(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en");
                    return;
                }
            }

            // Page the directory: the handle stays valid until EOF or CLOSE
            // (draft 6.7), so a repeated READDIR keeps streaming entries.
            if (entry.EofReached)
            {
                SendStatus(requestId, SSH_FX_EOF, "", "");
                return;
            }

            var files = entry.DirectoryHandle.ReadEntries(ReadDirBatchSize);
            if (files.Length == 0)
            {
                entry.EofReached = true;
                SendStatus(requestId, SSH_FX_EOF, "", "");
                return;
            }

            SendName(requestId, files);
        }

        private void ProcessRemove(SshDataReader reader, uint requestId)
        {
            var filename = reader.ReadString(Encoding.UTF8);

            if (!EnsureWritable(requestId))
                return;

            _fileSystem.RemoveFile(filename);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessRename(SshDataReader reader, uint requestId)
        {
            var oldPath = reader.ReadString(Encoding.UTF8);
            var newPath = reader.ReadString(Encoding.UTF8);

            if (!EnsureWritable(requestId))
                return;

            _fileSystem.Rename(oldPath, newPath);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessMakeDir(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);
            var attributes = SftpFileAttributes.Read(reader);

            if (!EnsureWritable(requestId))
                return;

            _fileSystem.MakeDirectory(path, attributes);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessRemoveDir(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            if (!EnsureWritable(requestId))
                return;

            _fileSystem.RemoveDirectory(path);
            SendStatus(requestId, SSH_FX_OK, "", "");
        }

        private void ProcessRealPath(SshDataReader reader, uint requestId)
        {
            var path = reader.ReadString(Encoding.UTF8);

            var realPath = _fileSystem.RealPath(path);
            var dummy = new SftpFileEntry { FileName = realPath, Attributes = new SftpFileAttributes() };
            SendName(requestId, [dummy]);
        }

        #endregion

        #region Handle registry

        private string RegisterHandle(HandleEntry entry)
        {
            var handle = Interlocked.Increment(ref _handleCursor).ToString();
            lock (_mapOfHandle)
                _mapOfHandle.Add(handle, entry);
            return handle;
        }

        /// <summary>Resolve a file handle, replying FAILURE when missing or a directory handle.</summary>
        private HandleEntry FindFileHandle(string handle, uint requestId)
        {
            HandleEntry entry;
            lock (_mapOfHandle)
            {
                if (!_mapOfHandle.TryGetValue(handle, out entry) || entry.Kind != HandleKind.File)
                {
                    SendStatus(requestId, SSH_FX_FAILURE, $"Unknown handle '{handle}'.", "en");
                    return null;
                }
            }
            return entry;
        }

        private enum HandleKind { File, Directory }

        private sealed class HandleEntry : IDisposable
        {
            public HandleKind Kind { get; private set; }
            public ISftpFileHandle FileHandle { get; private set; }
            public ISftpDirectoryHandle DirectoryHandle { get; private set; }

            /// <summary>True once a READDIR batch returned empty (draft 6.7 EOF).</summary>
            public bool EofReached { get; set; }

            public static HandleEntry ForFile(ISftpFileHandle handle)
                => new() { Kind = HandleKind.File, FileHandle = handle };

            public static HandleEntry ForDirectory(ISftpDirectoryHandle handle)
                => new() { Kind = HandleKind.Directory, DirectoryHandle = handle };

            public void Dispose()
            {
                FileHandle?.Dispose();
                DirectoryHandle?.Dispose();
            }
        }

        #endregion

        #region Response building

        private void SendPacket(byte[] packet)
        {
            // Length prefix = bytes after the length field itself (draft section 3).
            var length = packet.Length - 4;
            packet[0] = (byte)(length >> 24);
            packet[1] = (byte)(length >> 16);
            packet[2] = (byte)(length >> 8);
            packet[3] = (byte)(length & 0xFF);
            DataReceived?.Invoke(this, packet);
        }

        private void SendStatus(uint requestId, uint statusCode, string message, string language)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_STATUS);
            writer.Write(requestId);
            writer.Write(statusCode);
            writer.Write(message, Encoding.UTF8);   // draft section 7: message is UTF-8
            writer.Write(language, Encoding.ASCII);
            SendPacket(writer.ToByteArray());
        }

        private void SendInit(uint version)
        {
            using var writer = new SshDataWriter(9);
            writer.Write(0u);
            writer.Write(SSH_FXP_VERSION);
            writer.Write(version);
            SendPacket(writer.ToByteArray());
        }

        private void SendHandle(uint requestId, string handle)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_HANDLE);
            writer.Write(requestId);
            writer.Write(handle, Encoding.ASCII);
            SendPacket(writer.ToByteArray());
        }

        private void SendData(uint requestId, ReadOnlyMemory<byte> bytes)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_DATA);
            writer.Write(requestId);
            writer.WriteBinary(bytes);
            SendPacket(writer.ToByteArray());
        }

        private void SendName(uint requestId, SftpFileEntry[] entries)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_NAME);
            writer.Write(requestId);
            writer.Write((uint)entries.Length);
            foreach (var entry in entries)
            {
                writer.Write(entry.FileName, Encoding.UTF8);
                writer.Write(FormatLongName(entry), Encoding.UTF8);
                entry.Attributes.Write(writer);
            }
            SendPacket(writer.ToByteArray());
        }

        private void SendAttrs(uint requestId, SftpFileAttributes attributes)
        {
            using var writer = new SshDataWriter();
            writer.Write(0u);
            writer.Write(SSH_FXP_ATTRS);
            writer.Write(requestId);
            attributes.Write(writer);
            SendPacket(writer.ToByteArray());
        }

        /// <summary>
        /// ls -l style display string (draft section 7 recommends, but does
        /// not require, this format; clients must not parse it).
        /// </summary>
        private static string FormatLongName(SftpFileEntry entry)
        {
            var attrs = entry.Attributes;
            var perms = attrs?.Permissions ?? 0x81B6u;
            var type = (perms & 0xF000) switch
            {
                0x4000 => 'd',   // directory
                0xA000 => 'l',   // symbolic link
                _ => '-',
            };
            var size = attrs?.Size?.ToString() ?? "0";
            var mtime = attrs?.ModificationTime != null
                ? DateTimeOffset.FromUnixTimeSeconds(attrs.ModificationTime.Value).ToString("MMM d HH:mm", CultureInfo.InvariantCulture)
                : "Jan 1 00:00";
            return $"{type}{ModeString(perms)} 1 owner group {size,10} {mtime} {entry.FileName}";
        }

        private static string ModeString(uint perms)
        {
            Span<char> mode = stackalloc char[9];
            for (var i = 0; i < 3; i++)
            {
                var shift = 6 - i * 3;
                mode[i * 3 + 0] = (perms & (1u << (shift + 2))) != 0 ? 'r' : '-';
                mode[i * 3 + 1] = (perms & (1u << (shift + 1))) != 0 ? 'w' : '-';
                mode[i * 3 + 2] = (perms & (1u << shift)) != 0 ? 'x' : '-';
            }
            return new string(mode);
        }

        #endregion

        #region Error mapping

        /// <summary>
        /// Single mapping from backend exceptions to SSH_FX_* codes (draft
        /// section 7 status semantics): missing files map to NO_SUCH_FILE,
        /// access failures to PERMISSION_DENIED, everything else to FAILURE.
        /// </summary>
        private static (uint Code, string Message) MapException(Exception ex)
        {
            return ex switch
            {
                FileNotFoundException or DirectoryNotFoundException => (SSH_FX_NO_SUCH_FILE, ex.Message),
                UnauthorizedAccessException => (SSH_FX_PERMISSION_DENIED, ex.Message),
                ArgumentException => (SSH_FX_BAD_MESSAGE, ex.Message),
                IOException => (SSH_FX_FAILURE, ex.Message),
                _ => (SSH_FX_FAILURE, ex.Message),
            };
        }

        #endregion
    }
}
