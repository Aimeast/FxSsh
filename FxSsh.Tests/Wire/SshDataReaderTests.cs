using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Wire
{
    [TestClass]
    public sealed class SshDataReaderTests
    {
        [TestMethod]
        public void ReadBoolean_treats_only_zero_as_false()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x01, 0xFF });
            Assert.IsFalse(reader.ReadBoolean());
            Assert.IsTrue(reader.ReadBoolean());
            Assert.IsTrue(reader.ReadBoolean());
        }

        [TestMethod]
        public void ReadByte_advances_one_byte_per_call()
        {
            var reader = new SshDataReader(new byte[] { 0xAB, 0xCD });
            Assert.AreEqual((byte)0xAB, reader.ReadByte());
            Assert.AreEqual(1L, reader.DataAvailable);
            Assert.AreEqual((byte)0xCD, reader.ReadByte());
            Assert.AreEqual(0L, reader.DataAvailable);
        }

        [TestMethod]
        public void ReadUInt32_decodes_big_endian()
        {
            var reader = new SshDataReader(new byte[] { 0x01, 0x02, 0x03, 0x04 });
            Assert.AreEqual(0x01020304u, reader.ReadUInt32());
        }

        [TestMethod]
        public void ReadUInt32_decodes_max_value()
        {
            var reader = new SshDataReader(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
            Assert.AreEqual(uint.MaxValue, reader.ReadUInt32());
        }

        [TestMethod]
        public void ReadUInt64_decodes_big_endian()
        {
            var reader = new SshDataReader(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
            Assert.AreEqual(0x0102030405060708ul, reader.ReadUInt64());
        }

        [TestMethod]
        public void ReadBytesAsMemory_slices_without_copying()
        {
            var source = new byte[] { 0x0A, 0x0B, 0x0C };
            var reader = new SshDataReader(source);

            var view = reader.ReadBytesAsMemory(2);

            Assert.AreEqual(2, view.Length);
            Assert.AreEqual((byte)0x0A, view.Span[0]);
            Assert.AreEqual((byte)0x0B, view.Span[1]);

            // The returned memory aliases the source buffer rather than
            // being a copy: mutating the source is visible through the view.
            source[0] = 0x99;
            Assert.AreEqual((byte)0x99, view.Span[0]);
        }

        [TestMethod]
        public void ReadBytesAsMemory_beyond_end_throws_and_does_not_advance()
        {
            var reader = new SshDataReader(new byte[] { 0x01, 0x02 });

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => reader.ReadBytesAsMemory(3));
            Assert.AreEqual(2L, reader.DataAvailable);

            // The remaining data is still readable after a failed over-read.
            Assert.AreEqual((byte)0x01, reader.ReadByte());
        }

        [TestMethod]
        public void ReadBinary_reads_length_prefixed_payload()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x7F });

            var payload = reader.ReadBinary();

            CollectionAssert.AreEqual(new byte[] { 0x61, 0x62, 0x63 }, payload);
            Assert.AreEqual(1L, reader.DataAvailable);
        }

        [TestMethod]
        public void ReadBinary_with_length_beyond_end_throws()
        {
            var reader = new SshDataReader(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => reader.ReadBinary());
        }

        [TestMethod]
        public void ReadBinaryAsMemory_is_zero_copy()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB });

            var view = reader.ReadBinaryAsMemory();

            Assert.AreEqual(2, view.Length);
            Assert.AreEqual((byte)0xAA, view.Span[0]);
        }

        [TestMethod]
        public void ReadString_decodes_with_given_encoding()
        {
            var payload = Encoding.UTF8.GetBytes("SSH协议");
            var reader = new SshDataReader(
                new SshDataWriter().WriteBinary(payload).ToByteArray());

            Assert.AreEqual("SSH协议", reader.ReadString(Encoding.UTF8));
        }

        [TestMethod]
        public void ReadString_rejects_null_encoding()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            Assert.ThrowsExactly<ArgumentNullException>(() => reader.ReadString(null!));
        }

        [TestMethod]
        public void ReadMpint_zero_length_value_returns_single_zero_byte()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x00 });

            CollectionAssert.AreEqual(new byte[] { 0x00 }, reader.ReadMpint());
        }

        [TestMethod]
        public void ReadMpint_strips_redundant_leading_zero()
        {
            // 0x00 0x80 encodes +128; the padding zero is not part of the value.
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x00, 0x80 });

            CollectionAssert.AreEqual(new byte[] { 0x80 }, reader.ReadMpint());
        }

        [TestMethod]
        public void ReadMpint_passes_positive_value_through()
        {
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x01, 0x02 });

            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02 }, reader.ReadMpint());
        }

        [TestMethod]
        public void ReadMpint_of_lone_zero_byte_yields_empty_value()
        {
            // A one-byte payload containing only the padding zero strips to an
            // empty value - the documented inverse of the writer's zero case.
            var reader = new SshDataReader(new byte[] { 0x00, 0x00, 0x00, 0x01, 0x00 });

            CollectionAssert.AreEqual(new byte[] { }, reader.ReadMpint());
        }

        [TestMethod]
        public void GetRemainderBytes_does_not_advance()
        {
            var reader = new SshDataReader(new byte[] { 0x01, 0x02, 0x03 });
            reader.ReadByte();

            CollectionAssert.AreEqual(new byte[] { 0x02, 0x03 }, reader.GetRemainderBytes());
            CollectionAssert.AreEqual(new byte[] { 0x02, 0x03 }, reader.GetRemainderBytes());
            Assert.AreEqual(2L, reader.DataAvailable);
        }

        [TestMethod]
        public void Sequential_reads_track_the_cursor()
        {
            // uint32 + byte + mpint + string packed back to back.
            var writer = new SshDataWriter()
                .Write(0xDEADBEEFu)
                .Write((byte)0x42)
                .WriteMpint(new byte[] { 0x80 })
                .Write("abc", Encoding.ASCII);
            var reader = new SshDataReader(writer.ToByteArray());

            Assert.AreEqual(0xDEADBEEFu, reader.ReadUInt32());
            Assert.AreEqual((byte)0x42, reader.ReadByte());
            CollectionAssert.AreEqual(new byte[] { 0x80 }, reader.ReadMpint());
            Assert.AreEqual("abc", reader.ReadString(Encoding.ASCII));
            Assert.AreEqual(0L, reader.DataAvailable);
        }
    }
}
