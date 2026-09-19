using System;
using System.IO;
using System.Text;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// Exercises LocalFileSystem against a real temporary directory: chroot
    /// path resolution, escape prevention, file I/O, read-only gating.
    /// </summary>
    [TestClass]
    public sealed class LocalFileSystemTests
    {
        private string _root = null!;
        private LocalFileSystem _fileSystem = null!;

        [TestInitialize]
        public void CreateTempRoot()
        {
            _root = Path.Combine(Path.GetTempPath(), "fxssh-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
            _fileSystem = new LocalFileSystem(_root);
        }

        [TestCleanup]
        public void DeleteTempRoot()
        {
            if (Directory.Exists(_root))
                Directory.Delete(_root, recursive: true);
        }

        [TestMethod]
        public void RealPath_canonicalizes_inside_the_jail()
        {
            Assert.AreEqual("/", _fileSystem.RealPath(string.Empty));
            Assert.AreEqual("/", _fileSystem.RealPath("~"));
            Assert.AreEqual("/", _fileSystem.RealPath("/"));
            Assert.AreEqual("/foo", _fileSystem.RealPath("foo"));
            Assert.AreEqual("/foo/bar", _fileSystem.RealPath("foo/bar"));
        }

        [TestMethod]
        public void RealPath_rejects_path_traversal()
        {
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => _fileSystem.RealPath("../outside"));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => _fileSystem.RealPath("foo/../../.."));

            // The native separator escapes on every platform. ('\' is an
            // ordinary filename character on Linux, so a backslash path
            // cannot express traversal there.)
            var native = string.Join(Path.DirectorySeparatorChar, "..", "..", "..", "windows");
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => _fileSystem.RealPath(native));
        }

        [TestMethod]
        public void Open_write_read_round_trip()
        {
            var payload = Encoding.UTF8.GetBytes("local file content");

            using (var handle = _fileSystem.OpenFile("/file.txt", SftpOpenFlags.Write | SftpOpenFlags.Create, null))
            {
                handle.Write(0, payload);
            }

            using var reader = _fileSystem.OpenFile("/file.txt", SftpOpenFlags.Read, null);
            var buffer = new byte[64];
            var read = reader.Read(0, buffer);

            Assert.AreEqual(payload.Length, read);
            CollectionAssert.AreEqual(payload, buffer[..read]);
        }

        [TestMethod]
        public void Create_truncate_replaces_existing_content()
        {
            using (var handle = _fileSystem.OpenFile("/file.txt", SftpOpenFlags.Write | SftpOpenFlags.Create, null))
            {
                handle.Write(0, new byte[100]);
            }

            using (var handle = _fileSystem.OpenFile("/file.txt", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate, null))
            {
                handle.Write(0, new byte[] { 0x01 });
            }

            using var reader = _fileSystem.OpenFile("/file.txt", SftpOpenFlags.Read, null);
            Assert.AreEqual(1, reader.Read(0, new byte[16]));
        }

        [TestMethod]
        public void OpenFile_validates_flag_combinations()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => _fileSystem.OpenFile("/x", (SftpOpenFlags)0, null));
            Assert.ThrowsExactly<ArgumentException>(
                () => _fileSystem.OpenFile("/x", SftpOpenFlags.Truncate | SftpOpenFlags.Read, null));
        }

        [TestMethod]
        public void Exclusive_create_fails_when_the_file_exists()
        {
            using var first = _fileSystem.OpenFile("/x", SftpOpenFlags.Write | SftpOpenFlags.Create, null);

            Assert.ThrowsExactly<IOException>(
                () => _fileSystem.OpenFile("/x", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Exclusive, null));
        }

        [TestMethod]
        public void Attributes_report_size_and_reject_missing_paths()
        {
            File.WriteAllText(Path.Combine(_root, "file.txt"), "12345");

            var attrs = _fileSystem.GetAttributes("/file.txt", followLinks: true);
            Assert.AreEqual(5ul, attrs.Size);

            Assert.ThrowsExactly<FileNotFoundException>(() => _fileSystem.GetAttributes("/missing.txt", followLinks: true));
        }

        [TestMethod]
        public void SetAttributes_truncates_the_file()
        {
            File.WriteAllText(Path.Combine(_root, "file.txt"), "1234567890");

            _fileSystem.SetAttributes("/file.txt", new SftpFileAttributes { Size = 4 });

            Assert.AreEqual("1234", File.ReadAllText(Path.Combine(_root, "file.txt")));
        }

        [TestMethod]
        public void Directory_operations()
        {
            _fileSystem.MakeDirectory("/sub", null);
            Assert.IsTrue(Directory.Exists(Path.Combine(_root, "sub")));

            // Creating over an existing path fails.
            Assert.ThrowsExactly<IOException>(() => _fileSystem.MakeDirectory("/sub", null));

            File.WriteAllText(Path.Combine(_root, "sub", "entry.txt"), "x");

            using (var handle = _fileSystem.OpenDirectory("/sub"))
            {
                var entries = handle.ReadEntries(10);
                Assert.AreEqual(1, entries.Length);
                Assert.AreEqual("entry.txt", entries[0].FileName);
                Assert.AreEqual(0, handle.ReadEntries(10).Length); // exhausted
            }

            // Non-empty RMDIR fails; after removing the entry it succeeds.
            Assert.ThrowsExactly<IOException>(() => _fileSystem.RemoveDirectory("/sub"));
            File.Delete(Path.Combine(_root, "sub", "entry.txt"));
            _fileSystem.RemoveDirectory("/sub");
            Assert.IsFalse(Directory.Exists(Path.Combine(_root, "sub")));

            Assert.ThrowsExactly<DirectoryNotFoundException>(() => _fileSystem.RemoveDirectory("/never-existed"));
            Assert.ThrowsExactly<DirectoryNotFoundException>(() => _fileSystem.OpenDirectory("/never-existed"));
        }

        [TestMethod]
        public void Remove_and_rename_files()
        {
            File.WriteAllText(Path.Combine(_root, "a.txt"), "a");

            _fileSystem.Rename("/a.txt", "/b.txt");
            Assert.IsFalse(File.Exists(Path.Combine(_root, "a.txt")));
            Assert.IsTrue(File.Exists(Path.Combine(_root, "b.txt")));

            _fileSystem.RemoveFile("/b.txt");
            Assert.IsFalse(File.Exists(Path.Combine(_root, "b.txt")));

            // Removing a directory with RemoveFile is refused.
            Directory.CreateDirectory(Path.Combine(_root, "dir"));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => _fileSystem.RemoveFile("/dir"));
        }

        [TestMethod]
        public void ReadOnly_backend_refuses_every_mutation()
        {
            var readOnly = new LocalFileSystem(_root, readOnly: true);
            File.WriteAllText(Path.Combine(_root, "file.txt"), "x");

            Assert.ThrowsExactly<UnauthorizedAccessException>(
                () => readOnly.OpenFile("/file.txt", SftpOpenFlags.Write | SftpOpenFlags.Create, null));
            Assert.ThrowsExactly<UnauthorizedAccessException>(
                () => readOnly.SetAttributes("/file.txt", new SftpFileAttributes { Size = 1 }));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => readOnly.RemoveFile("/file.txt"));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => readOnly.Rename("/file.txt", "/y"));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => readOnly.MakeDirectory("/d", null));
            Assert.ThrowsExactly<UnauthorizedAccessException>(() => readOnly.RemoveDirectory("/d"));

            // Reads still work.
            using var handle = readOnly.OpenFile("/file.txt", SftpOpenFlags.Read, null);
            Assert.AreEqual(1, handle.Read(0, new byte[8]));
        }

        [TestMethod]
        public void Constructor_validates_the_root_path()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => new LocalFileSystem(null!));
        }
    }
}
