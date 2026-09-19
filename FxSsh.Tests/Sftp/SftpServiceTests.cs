using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// Drives the SFTP protocol engine through OnData with hand-built
    /// SSH_FXP_* frames and asserts the responses emitted on DataReceived.
    /// </summary>
    [TestClass]
    public sealed class SftpServiceTests
    {
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

        private const byte SSH_FXP_STATUS = 101;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_DATA = 103;
        private const byte SSH_FXP_NAME = 104;
        private const byte SSH_FXP_ATTRS = 105;

        private const uint SSH_FX_OK = 0;
        private const uint SSH_FX_EOF = 1;
        private const uint SSH_FX_NO_SUCH_FILE = 2;
        private const uint SSH_FX_PERMISSION_DENIED = 3;
        private const uint SSH_FX_FAILURE = 4;
        private const uint SSH_FX_BAD_MESSAGE = 5;
        private const uint SSH_FX_OP_UNSUPPORTED = 8;

        private readonly InMemorySftpFileSystem _fileSystem = new();
        private readonly List<byte[]> _outbound = [];
        private readonly SftpService _service;

        public SftpServiceTests()
        {
            _service = new SftpService(_fileSystem, readOnly: false);
            _service.DataReceived += (_, packet) => _outbound.Add(packet);
        }

        private static byte[] Frame(Action<SshDataWriter> writePayload)
        {
            var payload = new SshDataWriter();
            writePayload(payload);
            var bytes = payload.ToByteArray();

            var frame = new byte[4 + bytes.Length];
            frame[0] = (byte)(bytes.Length >> 24);
            frame[1] = (byte)(bytes.Length >> 16);
            frame[2] = (byte)(bytes.Length >> 8);
            frame[3] = (byte)bytes.Length;
            bytes.CopyTo(frame, 4);
            return frame;
        }

        private static byte[] Request(byte type, uint requestId, Action<SshDataWriter>? writeFields = null)
        {
            return Frame(writer =>
            {
                writer.Write(type);
                writer.Write(requestId);
                writeFields?.Invoke(writer);
            });
        }

        private (byte Type, uint Id, SshDataReader Payload) LastResponse()
        {
            Assert.IsTrue(_outbound.Count > 0, "expected a response packet");
            var reader = new SshDataReader(_outbound[^1]);
            var length = reader.ReadUInt32();
            var payload = reader.ReadBytes((int)length);

            var response = new SshDataReader(payload);
            var type = response.ReadByte();
            var id = type == SSH_FXP_VERSION ? 0u : response.ReadUInt32();
            return (type, id, response);
        }

        private uint AssertStatus(uint expectedCode)
        {
            var (type, id, payload) = LastResponse();
            Assert.AreEqual(SSH_FXP_STATUS, type, $"expected STATUS, got type {type}");
            Assert.AreEqual(expectedCode, payload.ReadUInt32());
            return id;
        }

        private static uint ReadStatusCode(byte[] packet, uint requestId)
        {
            var reader = new SshDataReader(packet);
            var length = reader.ReadUInt32();
            var payload = reader.ReadBytes((int)length);
            var response = new SshDataReader(payload);
            Assert.AreEqual(SSH_FXP_STATUS, response.ReadByte());
            Assert.AreEqual(requestId, response.ReadUInt32());
            return response.ReadUInt32();
        }

        private string OpenForWrite(uint requestId, string path)
        {
            _service.OnData(Request(SSH_FXP_OPEN, requestId, writer =>
            {
                writer.Write(path, Encoding.UTF8);
                writer.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Create));
                writer.Write(0u); // empty attributes
            }));

            var (type, id, payload) = LastResponse();
            Assert.AreEqual(SSH_FXP_HANDLE, type);
            Assert.AreEqual(requestId, id);
            return payload.ReadString(Encoding.ASCII);
        }

        [TestMethod]
        public void Init_negotiates_the_lowest_common_version()
        {
            _service.OnData(Frame(writer =>
            {
                writer.Write(SSH_FXP_INIT);
                writer.Write(6u);
                writer.Write("ext-name", Encoding.ASCII); // extension data is ignored
                writer.Write("ext-data", Encoding.UTF8);
            }));

            var (type, _, payload) = LastResponse();
            Assert.AreEqual(SSH_FXP_VERSION, type);
            Assert.AreEqual(3u, payload.ReadUInt32());

            _service.OnData(Frame(writer =>
            {
                writer.Write(SSH_FXP_INIT);
                writer.Write(2u);
            }));

            var second = LastResponse();
            Assert.AreEqual(SSH_FXP_VERSION, second.Type);
            Assert.AreEqual(2u, second.Payload.ReadUInt32());
        }

        [TestMethod]
        public void RealPath_returns_the_canonical_path_as_a_name_entry()
        {
            _service.OnData(Request(SSH_FXP_REALPATH, 7, writer => writer.Write("/tmp/file.txt", Encoding.UTF8)));

            var (type, id, payload) = LastResponse();
            Assert.AreEqual(SSH_FXP_NAME, type);
            Assert.AreEqual(7u, id);
            Assert.AreEqual(1u, payload.ReadUInt32());
            Assert.AreEqual("/tmp/file.txt", payload.ReadString(Encoding.UTF8));
            StringAssert.Contains(payload.ReadString(Encoding.UTF8), "/tmp/file.txt");
        }

        [TestMethod]
        public void Open_write_read_eof_close_cycle()
        {
            var payload = Encoding.UTF8.GetBytes("hello sftp");

            _service.OnData(Request(SSH_FXP_OPEN, 1, writer =>
            {
                writer.Write("/hello.txt", Encoding.UTF8);
                writer.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate));
                writer.Write(0u);
            }));

            var (type, id, handleReader) = LastResponse();
            Assert.AreEqual(SSH_FXP_HANDLE, type);
            Assert.AreEqual(1u, id);
            var handle = handleReader.ReadString(Encoding.ASCII);

            _service.OnData(Request(SSH_FXP_WRITE, 2, writer =>
            {
                writer.Write(handle, Encoding.ASCII);
                writer.Write(0ul);
                writer.WriteBinary(payload);
            }));
            AssertStatus(SSH_FX_OK);

            _service.OnData(Request(SSH_FXP_READ, 3, writer =>
            {
                writer.Write(handle, Encoding.ASCII);
                writer.Write(0ul);
                writer.Write(100u);
            }));

            var (readType, _, readRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_DATA, readType);
            CollectionAssert.AreEqual(payload, readRest.ReadBinary());

            _service.OnData(Request(SSH_FXP_READ, 4, writer =>
            {
                writer.Write(handle, Encoding.ASCII);
                writer.Write(1000ul);
                writer.Write(16u);
            }));
            AssertStatus(SSH_FX_EOF); // reading past EOF

            _service.OnData(Request(SSH_FXP_CLOSE, 5, writer => writer.Write(handle, Encoding.ASCII)));
            AssertStatus(SSH_FX_OK);

            CollectionAssert.AreEqual(payload, _fileSystem.Files["/hello.txt"]);

            // The handle is gone after CLOSE.
            _service.OnData(Request(SSH_FXP_READ, 6, writer =>
            {
                writer.Write(handle, Encoding.ASCII);
                writer.Write(0ul);
                writer.Write(16u);
            }));
            AssertStatus(SSH_FX_FAILURE);
        }

        [TestMethod]
        public void Open_rejects_invalid_flag_combinations()
        {
            // No access flag at all.
            _service.OnData(Request(SSH_FXP_OPEN, 1, writer =>
            {
                writer.Write("/x", Encoding.UTF8);
                writer.Write(0u);
                writer.Write(0u);
            }));
            AssertStatus(SSH_FX_BAD_MESSAGE);

            // TRUNC / EXCL without CREAT.
            foreach (var invalid in new[] { SftpOpenFlags.Truncate, SftpOpenFlags.Exclusive })
            {
                _service.OnData(Request(SSH_FXP_OPEN, 2, writer =>
                {
                    writer.Write("/x", Encoding.UTF8);
                    writer.Write((uint)(SftpOpenFlags.Read | invalid));
                    writer.Write(0u);
                }));
                AssertStatus(SSH_FX_BAD_MESSAGE);
            }

            Assert.AreEqual(0, _fileSystem.OpenPaths.Count);
        }

        [TestMethod]
        public void Read_write_reject_unknown_or_wrong_kind_handles()
        {
            _fileSystem.Directories.Add("/");

            _service.OnData(Request(SSH_FXP_READ, 1, writer =>
            {
                writer.Write("no-such-handle", Encoding.ASCII);
                writer.Write(0ul);
                writer.Write(16u);
            }));
            AssertStatus(SSH_FX_FAILURE);

            // A directory handle is not valid for READ...
            _service.OnData(Request(SSH_FXP_OPENDIR, 2, writer => writer.Write("/", Encoding.UTF8)));
            var (dirType, _, dirRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_HANDLE, dirType);
            var dirHandle = dirRest.ReadString(Encoding.ASCII);

            _service.OnData(Request(SSH_FXP_READ, 3, writer =>
            {
                writer.Write(dirHandle, Encoding.ASCII);
                writer.Write(0ul);
                writer.Write(16u);
            }));
            AssertStatus(SSH_FX_FAILURE);

            // ...and a file handle is not valid for READDIR.
            var fileHandle = OpenForWrite(4, "/file.txt");
            _service.OnData(Request(SSH_FXP_READDIR, 5, writer => writer.Write(fileHandle, Encoding.ASCII)));
            AssertStatus(SSH_FX_FAILURE);
        }

        [TestMethod]
        public void OpenDir_read_dir_eof_cycle()
        {
            _fileSystem.Directories.Add("/");
            _fileSystem.Files["/a.txt"] = [0x01];
            _fileSystem.Directories.Add("/sub");

            _service.OnData(Request(SSH_FXP_OPENDIR, 1, writer => writer.Write("/", Encoding.UTF8)));
            var (openType, _, openRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_HANDLE, openType);
            var handle = openRest.ReadString(Encoding.ASCII);

            _service.OnData(Request(SSH_FXP_READDIR, 2, writer => writer.Write(handle, Encoding.ASCII)));
            var (nameType, _, nameRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_NAME, nameType);

            // Entries are (filename, longname, attributes) triples: walk all
            // three fields to collect every name in the batch.
            Assert.AreEqual(2u, nameRest.ReadUInt32());
            var names = new List<string>();
            for (var i = 0; i < 2; i++)
            {
                names.Add(nameRest.ReadString(Encoding.UTF8));
                nameRest.ReadString(Encoding.UTF8); // longname
                SkipAttributes(nameRest);
            }

            CollectionAssert.AreEquivalent(new[] { "a.txt", "sub" }, names);

            // Directory exhausted: the next READDIR reports EOF.
            _service.OnData(Request(SSH_FXP_READDIR, 3, writer => writer.Write(handle, Encoding.ASCII)));
            AssertStatus(SSH_FX_EOF);

            _service.OnData(Request(SSH_FXP_CLOSE, 4, writer => writer.Write(handle, Encoding.ASCII)));
            AssertStatus(SSH_FX_OK);
        }

        private static void SkipAttributes(SshDataReader reader)
        {
            var flags = reader.ReadUInt32();
            if ((flags & 0x1) != 0)
                reader.ReadUInt64();
            if ((flags & 0x2) != 0)
            {
                reader.ReadUInt32();
                reader.ReadUInt32();
            }

            if ((flags & 0x4) != 0)
                reader.ReadUInt32();
            if ((flags & 0x8) != 0)
            {
                reader.ReadUInt32();
                reader.ReadUInt32();
            }

            if ((flags & 0x80000000) != 0)
            {
                var count = reader.ReadUInt32();
                for (var i = 0; i < count; i++)
                {
                    reader.ReadString(Encoding.ASCII);
                    reader.ReadString(Encoding.UTF8);
                }
            }
        }

        [TestMethod]
        public void ReadOnly_mode_gates_every_mutation()
        {
            var readOnlyFs = new InMemorySftpFileSystem();
            var received = new List<byte[]>();
            var readOnlyService = new SftpService(readOnlyFs, readOnly: true);
            readOnlyService.DataReceived += (_, packet) => received.Add(packet);

            void OnData(byte[] frame) => readOnlyService.OnData(frame);

            // OPEN requesting write capability is denied outright.
            OnData(Request(SSH_FXP_OPEN, 1, writer =>
            {
                writer.Write("/x", Encoding.UTF8);
                writer.Write((uint)(SftpOpenFlags.Write | SftpOpenFlags.Create));
                writer.Write(0u);
            }));
            Assert.AreEqual(SSH_FX_PERMISSION_DENIED, ReadStatusCode(received[^1], 1));

            // Pure-read OPEN passes even in read-only mode.
            readOnlyFs.Files["/r.txt"] = [0x00];
            OnData(Request(SSH_FXP_OPEN, 2, writer =>
            {
                writer.Write("/r.txt", Encoding.UTF8);
                writer.Write((uint)SftpOpenFlags.Read);
                writer.Write(0u);
            }));

            var openReader = new SshDataReader(received[^1]);
            openReader.ReadUInt32();
            var openPayload = openReader.ReadBytes((int)(received[^1].Length - 4));
            Assert.AreEqual(SSH_FXP_HANDLE, openPayload[0]);
            var openRest = new SshDataReader(openPayload[5..]);
            var readOnlyHandle = openRest.ReadString(Encoding.ASCII);

            // WRITE on that handle is denied by the engine (before the
            // backend is consulted).
            OnData(Request(SSH_FXP_WRITE, 3, writer =>
            {
                writer.Write(readOnlyHandle, Encoding.ASCII);
                writer.Write(0ul);
                writer.WriteBinary(new byte[] { 0xFF });
            }));
            Assert.AreEqual(SSH_FX_PERMISSION_DENIED, ReadStatusCode(received[^1], 3));

            var mutatingRequests = new (byte Type, Action<SshDataWriter> Fields)[]
            {
                (SSH_FXP_REMOVE, w => w.Write("/r.txt", Encoding.UTF8)),
                (SSH_FXP_RENAME, w => { w.Write("/a", Encoding.UTF8); w.Write("/b", Encoding.UTF8); }),
                (SSH_FXP_MKDIR, w => { w.Write("/d", Encoding.UTF8); w.Write(0u); }),
                (SSH_FXP_RMDIR, w => w.Write("/d", Encoding.UTF8)),
                (SSH_FXP_SETSTAT, w => { w.Write("/r.txt", Encoding.UTF8); w.Write(0u); }),
                (SSH_FXP_FSETSTAT, w => { w.Write("0", Encoding.ASCII); w.Write(0u); }),
            };

            foreach (var (type, fields) in mutatingRequests)
            {
                OnData(Request(type, 10, fields));
                Assert.AreEqual(SSH_FX_PERMISSION_DENIED, ReadStatusCode(received[^1], 10));
            }

            Assert.AreEqual(0, readOnlyFs.SetAttributesCalls);
            Assert.AreEqual(0, readOnlyFs.Renames.Count);
            Assert.AreEqual(0, readOnlyFs.CreatedDirectories.Count);
        }

        [TestMethod]
        public void Stat_fstat_and_setstat_delegate_to_the_backend()
        {
            _fileSystem.Files["/file.txt"] = new byte[42];

            _service.OnData(Request(SSH_FXP_STAT, 1, writer => writer.Write("/file.txt", Encoding.UTF8)));
            var (statType, _, statRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_ATTRS, statType);
            var attrs = SftpFileAttributes.Read(statRest);
            Assert.AreEqual(42ul, attrs.Size);

            _service.OnData(Request(SSH_FXP_LSTAT, 2, writer => writer.Write("/file.txt", Encoding.UTF8)));
            Assert.AreEqual(SSH_FXP_ATTRS, LastResponse().Type);

            _service.OnData(Request(SSH_FXP_SETSTAT, 3, writer =>
            {
                writer.Write("/file.txt", Encoding.UTF8);
                writer.Write(0u); // empty attribute set
            }));
            AssertStatus(SSH_FX_OK);
            Assert.AreEqual(1, _fileSystem.SetAttributesCalls);
        }

        [TestMethod]
        public void Fstat_reports_the_open_file_attributes()
        {
            var handle = OpenForWrite(1, "/f.txt");

            _service.OnData(Request(SSH_FXP_FSTAT, 2, writer => writer.Write(handle, Encoding.ASCII)));
            var (type, _, rest) = LastResponse();
            Assert.AreEqual(SSH_FXP_ATTRS, type);
            Assert.IsNotNull(SftpFileAttributes.Read(rest));
        }

        [TestMethod]
        public void Remove_rename_mkdir_rmdir_delegate_to_the_backend()
        {
            _service.OnData(Request(SSH_FXP_REMOVE, 1, writer => writer.Write("/gone.txt", Encoding.UTF8)));
            AssertStatus(SSH_FX_OK);

            _service.OnData(Request(SSH_FXP_RENAME, 2, writer =>
            {
                writer.Write("/old", Encoding.UTF8);
                writer.Write("/new", Encoding.UTF8);
            }));
            AssertStatus(SSH_FX_OK);

            _service.OnData(Request(SSH_FXP_MKDIR, 3, writer =>
            {
                writer.Write("/newdir", Encoding.UTF8);
                writer.Write(0u);
            }));
            AssertStatus(SSH_FX_OK);

            _service.OnData(Request(SSH_FXP_RMDIR, 4, writer => writer.Write("/olddir", Encoding.UTF8)));
            AssertStatus(SSH_FX_OK);

            CollectionAssert.AreEqual(new[] { "/gone.txt" }, _fileSystem.RemovedFiles);
            CollectionAssert.AreEqual(new[] { ("/old", "/new") }, _fileSystem.Renames);
            CollectionAssert.AreEqual(new[] { "/newdir" }, _fileSystem.CreatedDirectories);
            CollectionAssert.AreEqual(new[] { "/olddir" }, _fileSystem.RemovedDirectories);
        }

        [TestMethod]
        public void Unsupported_and_unknown_operations_report_op_unsupported()
        {
            foreach (var (type, fields) in new (byte, Action<SshDataWriter>)[]
            {
                (SSH_FXP_READLINK, w => w.Write("/link", Encoding.UTF8)),
                (SSH_FXP_SYMLINK, w => { w.Write("/target", Encoding.UTF8); w.Write("/link", Encoding.UTF8); }),
                (SSH_FXP_EXTENDED, w => w.Write("hardlink@openssh.com", Encoding.UTF8)),
            })
            {
                _service.OnData(Request(type, 1, fields));
                AssertStatus(SSH_FX_OP_UNSUPPORTED);
            }

            // Unknown packet type: answered with OP_UNSUPPORTED, not a crash.
            _service.OnData(Request(250, 2));
            var (unknownType, _, unknownRest) = LastResponse();
            Assert.AreEqual(SSH_FXP_STATUS, unknownType);
            Assert.AreEqual(SSH_FX_OP_UNSUPPORTED, unknownRest.ReadUInt32());
        }

        [TestMethod]
        public void Backend_exceptions_map_to_status_codes()
        {
            (Exception Exception, uint ExpectedCode)[] cases =
            {
                (new FileNotFoundException("missing"), SSH_FX_NO_SUCH_FILE),
                (new DirectoryNotFoundException("missing dir"), SSH_FX_NO_SUCH_FILE),
                (new UnauthorizedAccessException("denied"), SSH_FX_PERMISSION_DENIED),
                (new ArgumentException("bad arg"), SSH_FX_BAD_MESSAGE),
                (new IOException("io"), SSH_FX_FAILURE),
                (new InvalidOperationException("boom"), SSH_FX_FAILURE),
            };

            foreach (var (exception, expectedCode) in cases)
            {
                var received = new List<byte[]>();
                var failing = new SftpService(new FaultyFileSystem(exception));
                failing.DataReceived += (_, p) => received.Add(p);

                failing.OnData(Request(SSH_FXP_REALPATH, 9, writer => writer.Write("/x", Encoding.UTF8)));

                Assert.AreEqual(1, received.Count, $"response count for {exception.GetType().Name}");
                Assert.AreEqual(expectedCode, ReadStatusCode(received[0], 9), $"mapping of {exception.GetType().Name}");
            }
        }

        [TestMethod]
        public void Frame_parser_reassembles_frames_split_across_calls()
        {
            var frame = Frame(writer =>
            {
                writer.Write(SSH_FXP_INIT);
                writer.Write(3u);
            });

            _service.OnData(frame[..3]);   // partial length prefix + payload
            Assert.AreEqual(0, _outbound.Count);

            _service.OnData(frame[3..]);
            Assert.AreEqual(SSH_FXP_VERSION, LastResponse().Type);
        }

        [TestMethod]
        public void Frame_parser_processes_multiple_frames_in_one_call()
        {
            var frame = Frame(writer =>
            {
                writer.Write(SSH_FXP_INIT);
                writer.Write(3u);
            });

            _service.OnData(frame.Concat(frame).ToArray());

            Assert.AreEqual(2, _outbound.Count);
        }

        [TestMethod]
        public void Invalid_frame_length_discards_the_buffer_without_crashing()
        {
            // Zero length prefix.
            _service.OnData(new byte[] { 0x00, 0x00, 0x00, 0x00 });
            Assert.AreEqual(0, _outbound.Count);

            // Oversized length prefix (> 1 MiB cap).
            _service.OnData(new byte[] { 0x00, 0x20, 0x00, 0x00, 0x01 });
            Assert.AreEqual(0, _outbound.Count);

            // The engine keeps working afterwards.
            _service.OnData(Frame(writer =>
            {
                writer.Write(SSH_FXP_INIT);
                writer.Write(3u);
            }));
            Assert.AreEqual(SSH_FXP_VERSION, LastResponse().Type);
        }

        [TestMethod]
        public void OnClose_disposes_handles_and_raises_close_received()
        {
            _ = OpenForWrite(1, "/open.txt");
            var handle = _fileSystem.LastFileHandle;
            Assert.IsNotNull(handle);
            Assert.IsFalse(handle.Disposed);

            uint? exitCode = null;
            _service.CloseReceived += (_, code) => exitCode = code;

            _service.OnClose();

            Assert.IsTrue(handle.Disposed);
            Assert.AreEqual(0u, exitCode);
        }

        [TestMethod]
        public void Dispose_releases_every_open_handle()
        {
            _ = OpenForWrite(1, "/one.txt");
            var handle = _fileSystem.LastFileHandle;
            Assert.IsNotNull(handle);

            _service.Dispose();

            Assert.IsTrue(handle.Disposed);
        }
    }
}
