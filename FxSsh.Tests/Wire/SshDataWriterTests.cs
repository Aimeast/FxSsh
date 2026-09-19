using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Wire
{
    [TestClass]
    public sealed class SshDataWriterTests
    {
        [TestMethod]
        public void Write_bool_emits_single_byte()
        {
            CollectionAssert.AreEqual(new byte[] { 0x01 }, new SshDataWriter().Write(true).ToByteArray());
            CollectionAssert.AreEqual(new byte[] { 0x00 }, new SshDataWriter().Write(false).ToByteArray());
        }

        [TestMethod]
        public void Write_byte_emits_single_byte()
        {
            CollectionAssert.AreEqual(new byte[] { 0xAB }, new SshDataWriter().Write((byte)0xAB).ToByteArray());
        }

        [TestMethod]
        public void Write_uint32_emits_big_endian()
        {
            var bytes = new SshDataWriter().Write(0x01020304u).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04 }, bytes);
        }

        [TestMethod]
        public void Write_uint64_emits_big_endian()
        {
            var bytes = new SshDataWriter().Write(0x0102030405060708ul).ToByteArray();

            CollectionAssert.AreEqual(
                new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
                bytes);
        }

        [TestMethod]
        public void Write_string_emits_length_prefixed_encoded_bytes()
        {
            var bytes = new SshDataWriter().Write("hi", Encoding.ASCII).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x68, 0x69 }, bytes);
        }

        [TestMethod]
        public void Write_binary_emits_length_prefixed_payload()
        {
            var bytes = new SshDataWriter().WriteBinary(new byte[] { 0xAA, 0xBB }).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB }, bytes);
        }

        [TestMethod]
        public void Write_mpint_zero_byte_becomes_zero_length_value()
        {
            var bytes = new SshDataWriter().WriteMpint(new byte[] { 0x00 }).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x00 }, bytes);
        }

        [TestMethod]
        public void Write_mpint_positive_value_without_padding()
        {
            var bytes = new SshDataWriter().WriteMpint(new byte[] { 0x01, 0x02 }).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x01, 0x02 }, bytes);
        }

        [TestMethod]
        public void Write_mpint_high_bit_inserts_sign_padding()
        {
            // 0x80 would read back as a negative number, so a 0x00 is inserted.
            var bytes = new SshDataWriter().WriteMpint(new byte[] { 0x80 }).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x00, 0x80 }, bytes);
        }

        [TestMethod]
        public void Write_mpint_multi_byte_high_bit_inserts_one_padding_byte()
        {
            var bytes = new SshDataWriter().WriteMpint(new byte[] { 0xFF, 0xEE }).ToByteArray();

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x03, 0x00, 0xFF, 0xEE }, bytes);
        }

        [TestMethod]
        public void WriteMpint_and_ReadMpint_round_trip()
        {
            byte[][] values =
            {
                new byte[] { 0x00 },
                new byte[] { 0x01 },
                new byte[] { 0x7F },
                new byte[] { 0x80 },
                new byte[] { 0x01, 0x00 },
                new byte[] { 0xFF, 0xEE, 0xDD },
                new byte[] { 0x8F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            };

            foreach (var value in values)
            {
                var writer = new SshDataWriter();
                writer.WriteMpint(value);
                var reader = new SshDataReader(writer.ToByteArray());

                CollectionAssert.AreEqual(value, reader.ReadMpint(), $"mpint {Convert.ToHexString(value)}");
            }
        }

        [TestMethod]
        public void Fluent_calls_return_the_same_writer()
        {
            var writer = new SshDataWriter();

            Assert.AreSame(writer, writer.Write((byte)1).Write(2u).WriteBinary(new byte[] { 3 }));
        }

        [TestMethod]
        public void Length_tracks_bytes_written()
        {
            var writer = new SshDataWriter();

            Assert.AreEqual(0, writer.Length);
            writer.Write((byte)1);
            Assert.AreEqual(1, writer.Length);
            writer.Write(1u);
            Assert.AreEqual(5, writer.Length);
            writer.Write("ab", Encoding.ASCII);
            Assert.AreEqual(5 + 6, writer.Length);
        }

        [TestMethod]
        public void Writer_grows_beyond_initial_capacity()
        {
            var writer = new SshDataWriter(expectedCapacity: 2);
            var payload = new byte[300];
            for (var i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)(i & 0xFF);
            }

            var bytes = writer.WriteBinary(payload).ToByteArray();

            Assert.AreEqual(4 + payload.Length, bytes.Length);
            Assert.AreEqual(300u, (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]));
            for (var i = 0; i < payload.Length; i++)
            {
                Assert.AreEqual(payload[i], bytes[4 + i], $"offset {i}");
            }
        }

        [TestMethod]
        public void AsMemory_exposes_written_bytes_until_disposed()
        {
            var writer = new SshDataWriter();
            writer.Write(0x01020304u);

            var memory = writer.AsMemory();

            Assert.AreEqual(4, memory.Length);
            Assert.AreEqual((byte)0x01, memory.Span[0]);

            writer.Dispose();
            Assert.ThrowsExactly<ObjectDisposedException>(() => writer.AsMemory());
        }

        [TestMethod]
        public void ToByteArray_is_one_shot()
        {
            var writer = new SshDataWriter();
            writer.Write((byte)0x42);

            var bytes = writer.ToByteArray();
            CollectionAssert.AreEqual(new byte[] { 0x42 }, bytes);

            // The writer self-disposes after the copy; reuse is rejected.
            Assert.ThrowsExactly<ObjectDisposedException>(() => writer.ToByteArray());
            Assert.ThrowsExactly<ObjectDisposedException>(() => writer.Write((byte)1));
        }

        [TestMethod]
        public void TryWriteTo_copies_when_destination_is_large_enough()
        {
            var writer = new SshDataWriter();
            writer.Write(0x01020304u);
            var destination = new byte[8];

            Assert.IsTrue(writer.TryWriteTo(destination));

            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00 }, destination);
            Assert.ThrowsExactly<ObjectDisposedException>(() => writer.AsMemory());
        }

        [TestMethod]
        public void TryWriteTo_returns_false_without_disposing_when_destination_is_too_small()
        {
            var writer = new SshDataWriter();
            writer.Write(0x01020304u);
            var tooSmall = new byte[3];

            Assert.IsFalse(writer.TryWriteTo(tooSmall));

            // Still usable: a retry with enough space succeeds.
            Assert.AreEqual(4, writer.Length);
            var rightSize = new byte[4];
            Assert.IsTrue(writer.TryWriteTo(rightSize));
            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04 }, rightSize);
        }

        [TestMethod]
        public void Dispose_is_idempotent()
        {
            var writer = new SshDataWriter();
            writer.Write((byte)1);
            writer.Dispose();
            writer.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => writer.Write((byte)1));
        }

        [TestMethod]
        public void Using_dispose_releases_rental_immediately()
        {
            byte[] bytes;
            using (var writer = new SshDataWriter())
            {
                writer.Write("ok", Encoding.ASCII);
                bytes = writer.ToByteArray();
            }

            CollectionAssert.AreEqual(new byte[] { 0x00, 0x00, 0x00, 0x02, 0x6F, 0x6B }, bytes);
        }
    }
}
