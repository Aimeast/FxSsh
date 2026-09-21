using System;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    [TestClass]
    public sealed class SftpFileAttributesTests
    {
        [TestMethod]
        public void Empty_attributes_have_zero_flags()
        {
            var attrs = new SftpFileAttributes();

            Assert.AreEqual(0u, attrs.Flags);
        }

        [TestMethod]
        public void Write_then_read_round_trips_every_field()
        {
            var attrs = new SftpFileAttributes
            {
                Size = 0x1122334455667788,
                UserId = 1000,
                GroupId = 2000,
                Permissions = 0x81A4,
                AccessTime = 1700000000,
                ModificationTime = 1700000001,
                Extended = new[] { ("name@openssh.com", "value") },
            };

            var writer = new SshDataWriter();
            attrs.Write(writer);
            var reader = new SshDataReader(writer.ToByteArray());
            var parsed = SftpFileAttributes.Read(reader);

            Assert.AreEqual(attrs.Size, parsed.Size);
            Assert.AreEqual(attrs.UserId, parsed.UserId);
            Assert.AreEqual(attrs.GroupId, parsed.GroupId);
            Assert.AreEqual(attrs.Permissions, parsed.Permissions);
            Assert.AreEqual(attrs.AccessTime, parsed.AccessTime);
            Assert.AreEqual(attrs.ModificationTime, parsed.ModificationTime);
            Assert.IsNotNull(parsed.Extended);
            Assert.AreEqual(1, parsed.Extended!.Length);
            Assert.AreEqual("name@openssh.com", parsed.Extended[0].Type);
            Assert.AreEqual("value", parsed.Extended[0].Data);
        }

        [TestMethod]
        public void Size_only_round_trip()
        {
            var attrs = new SftpFileAttributes { Size = 7 };

            var writer = new SshDataWriter();
            attrs.Write(writer);
            var parsed = SftpFileAttributes.Read(new SshDataReader(writer.ToByteArray()));

            Assert.AreEqual(7ul, parsed.Size);
            Assert.IsNull(parsed.Permissions);
            Assert.IsNull(parsed.UserId);
            Assert.IsNull(parsed.ModificationTime);
            Assert.IsNull(parsed.Extended);
        }

        [TestMethod]
        public void Permissions_only_round_trip()
        {
            var attrs = new SftpFileAttributes { Permissions = 0x41ED };

            var writer = new SshDataWriter();
            attrs.Write(writer);
            var parsed = SftpFileAttributes.Read(new SshDataReader(writer.ToByteArray()));

            Assert.AreEqual(0x41EDu, parsed.Permissions);
            Assert.IsNull(parsed.Size);
        }

        [TestMethod]
        public void Times_only_round_trip()
        {
            var attrs = new SftpFileAttributes { AccessTime = 111, ModificationTime = 222 };

            var writer = new SshDataWriter();
            attrs.Write(writer);
            var parsed = SftpFileAttributes.Read(new SshDataReader(writer.ToByteArray()));

            Assert.AreEqual(111u, parsed.AccessTime);
            Assert.AreEqual(222u, parsed.ModificationTime);
        }

        [TestMethod]
        public void Read_of_empty_flags_yields_all_nulls()
        {
            var parsed = SftpFileAttributes.Read(new SshDataReader(new byte[] { 0, 0, 0, 0 }));

            Assert.IsNull(parsed.Size);
            Assert.IsNull(parsed.UserId);
            Assert.IsNull(parsed.GroupId);
            Assert.IsNull(parsed.Permissions);
            Assert.IsNull(parsed.AccessTime);
            Assert.IsNull(parsed.ModificationTime);
            Assert.IsNull(parsed.Extended);
        }

        [TestMethod]
        public void Write_rejects_null_writer()
        {
            Assert.ThrowsExactly<ArgumentNullException>(
                () => new SftpFileAttributes().Write(null!));
            Assert.ThrowsExactly<ArgumentNullException>(
                () => SftpFileAttributes.Read(null!));
        }
    }
}
