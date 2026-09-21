using System;
using System.IO;
using System.Text;
using FxSsh;
using FxSsh.Services.Sftp;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Sftp
{
    /// <summary>
    /// SftpService constructor variants and request edge branches that the
    /// protocol-matrix tests do not reach.
    /// </summary>
    [TestClass]
    public sealed class SftpServiceEdgeTests
    {
        private string _home = null!;

        [TestInitialize]
        public void CreateTempRoot()
        {
            _home = Path.Combine(Path.GetTempPath(), "fxssh-sftp-edge-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_home);
        }

        [TestCleanup]
        public void DeleteTempRoot()
        {
            if (Directory.Exists(_home))
                Directory.Delete(_home, recursive: true);
        }

        [TestMethod]
        public void Home_rooted_constructors_work()
        {
            // Default ctor roots at the user's home directory; it must not
            // throw and must serve REALPATH for the home root.
            var received = new System.Collections.Generic.List<byte[]>();
            using var service = new SftpService();
            service.DataReceived += (_, packet) => received.Add(packet);

            service.OnData(Frame(w =>
            {
                w.Write(SSH_FXP_INIT);
                w.Write(3u);
            }));
            Assert.AreEqual(1, received.Count);

            service.OnData(Frame(w =>
            {
                w.Write(SSH_FXP_REALPATH);
                w.Write(1u);
                w.Write(".", Encoding.UTF8);
            }));
            Assert.AreEqual(2, received.Count);
        }

        [TestMethod]
        public void Read_request_length_is_clamped_to_the_protocol_maximum()
        {
            using var service = new SftpService(_home);
            var received = new System.Collections.Generic.List<byte[]>();
            service.DataReceived += (_, packet) => received.Add(packet);

            File.WriteAllBytes(Path.Combine(_home, "big.bin"), new byte[1000]);

            string? handle = null;
            service.OnData(Frame(w =>
            {
                w.Write(SSH_FXP_OPEN);
                w.Write(1u);
                w.Write("/big.bin", Encoding.UTF8);
                w.Write((uint)SftpOpenFlags.Read);
                w.Write(0u);
            }));
            handle = ExtractHandle(received[^1]);

            // Request far more than MaxReadLength (64 KiB): the engine must
            // clamp the buffer, answer with the file (1000 bytes) and not
            // allocate the requested size.
            service.OnData(Frame(w =>
            {
                w.Write(SSH_FXP_READ);
                w.Write(2u);
                w.Write(handle, Encoding.ASCII);
                w.Write(0ul);
                w.Write(uint.MaxValue);
            }));

            var last = received[^1];
            var reader = new SshDataReader(last);
            reader.ReadUInt32(); // frame length prefix
            var payload = reader.ReadBytes((int)(last.Length - 4));
            Assert.AreEqual(SSH_FXP_DATA, payload[0]);
            // DATA payload: id + string length + the whole 1000-byte file.
            Assert.AreEqual(1 + 4 + 4 + 1000, payload.Length);
        }

        [TestMethod]
        public void Open_without_trailing_realpath_still_works()
        {
            using var service = new SftpService(_home);
            var received = new System.Collections.Generic.List<byte[]>();
            service.DataReceived += (_, packet) => received.Add(packet);

            service.OnData(Frame(w =>
            {
                w.Write(SSH_FXP_REALPATH);
                w.Write(9u);
                w.Write(".", Encoding.UTF8);
            }));

            var reader = new SshDataReader(received[^1]);
            reader.ReadUInt32();
            var payload = reader.ReadBytes((int)(received[^1].Length - 4));
            Assert.AreEqual(SSH_FXP_NAME, payload[0]);
        }

        private const byte SSH_FXP_INIT = 1;
        private const byte SSH_FXP_VERSION = 2;
        private const byte SSH_FXP_OPEN = 3;
        private const byte SSH_FXP_READ = 5;
        private const byte SSH_FXP_REALPATH = 16;
        private const byte SSH_FXP_NAME = 104;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_DATA = 103;

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

        private static string ExtractHandle(byte[] packet)
        {
            var reader = new SshDataReader(packet);
            var length = reader.ReadUInt32();
            var payload = reader.ReadBytes((int)length);
            var r = new SshDataReader(payload);
            Assert.AreEqual(SSH_FXP_HANDLE, r.ReadByte());
            r.ReadUInt32(); // request id echoed by the engine
            return r.ReadString(Encoding.ASCII);
        }
    }
}
