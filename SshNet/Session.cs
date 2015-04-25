using SshNet.Algorithms;
using SshNet.Messages;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SshNet
{
    public class Session
    {
        private const byte Null = 0x00;
        private const byte CarriageReturn = 0x0d;
        private const byte LineFeed = 0x0a;
        private const int MaximumSshPacketSize = LocalChannelDataPacketSize + 3000;
        private const int InitialLocalWindowSize = LocalChannelDataPacketSize * 32;
        private const int LocalChannelDataPacketSize = 1024 * 64;

        private readonly Socket _socket;
#if DEBUG
        private readonly TimeSpan _timeout = TimeSpan.FromDays(1);
#else
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
#endif
        private readonly Dictionary<string, Func<AsymmetricAlgorithm, KexAlgorithm>> _keyExchangeAlgorithms =
            new Dictionary<string, Func<AsymmetricAlgorithm, KexAlgorithm>>();
        private readonly Dictionary<string, Func<string, PublicKeyAlgorithm>> _publicKeyAlgorithms =
            new Dictionary<string, Func<string, PublicKeyAlgorithm>>();
        private readonly Dictionary<string, Func<byte[], byte[], EncryptionAlgorithm>> _encryptionAlgorithms =
            new Dictionary<string, Func<byte[], byte[], EncryptionAlgorithm>>();
        private readonly Dictionary<string, Func<byte[], HmacAlgorithm>> _hmacAlgorithms =
            new Dictionary<string, Func<byte[], HmacAlgorithm>>();
        private readonly Dictionary<string, Func<CompressionAlgorithm>> _compressionAlgorithms =
            new Dictionary<string, Func<CompressionAlgorithm>>();

        public string ServerVersion { get; private set; }
        public string ClientVersion { get; private set; }

        public Session(Socket socket)
        {
            Contract.Requires(socket != null);

            _socket = socket;
            ServerVersion = "SSH-2.0-SshNet";
        }

        public event EventHandler<EventArgs> Disconnected;

        public bool IsConnected { get; private set; }

        public void EstablishConnection()
        {
            if (IsConnected)
                return;

            SetSocketOptions();

            SocketWriteLine(ServerVersion);
            ClientVersion = SocketReadLine();
            var clientIdVersions = ClientVersion.Split('-')[1];
            if (clientIdVersions != "2.0")
            {
                Disconnect(DisconnectReason.ProtocolVersionNotSupported, "This server only supports SSH v2.0.");
                throw new NotSupportedException(
                    string.Format("Not supported for client SSH version {0}. This server only supports SSH v2.0.", clientIdVersions));
            }

            RegisterAlgorithms();
        }

        public void Disconnect()
        {
            Disconnect(DisconnectReason.ByApplication, "Connection terminated by the server.");
        }

        public void Disconnect(DisconnectReason reason, string description)
        {
            if (reason == DisconnectReason.ByApplication)
            {
                var message = new DisconnectMessage(reason, description);
                TrySendMessage(message);
            }

            _socket.Disconnect(true);
            _socket.Dispose();

            if (Disconnected != null)
                Disconnected(this, EventArgs.Empty);
        }

        private void SetSocketOptions()
        {
            const int socketBufferSize = 2 * MaximumSshPacketSize;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendBuffer, socketBufferSize);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, socketBufferSize);
        }

        private string SocketReadLine()
        {
            var encoding = Encoding.ASCII;
            var buffer = new List<byte>();
            var data = new byte[1];

            // read data one byte at a time to find end of line and leave any unhandled information in the buffer
            // to be processed by subsequent invocations
            do
            {
                var asyncResult = _socket.BeginReceive(data, 0, data.Length, SocketFlags.None, null, null);
                if (!asyncResult.AsyncWaitHandle.WaitOne(_timeout))
                    throw new TimeoutException(string.Format(CultureInfo.InvariantCulture,
                        "Socket read operation has timed out after {0:F0} milliseconds.", _timeout.TotalMilliseconds));

                var received = _socket.EndReceive(asyncResult);

                if (received == 0)
                    // the remote server shut down the socket
                    break;

                buffer.Add(data[0]);
            }
            while (!(buffer.Count > 0 && (buffer[buffer.Count - 1] == LineFeed || buffer[buffer.Count - 1] == Null)));

            if (buffer.Count == 0)
                return null;
            else if (buffer.Count == 1 && buffer[buffer.Count - 1] == 0x00)
                // return an empty version string if the buffer consists of only a 0x00 character
                return string.Empty;
            else if (buffer.Count > 1 && buffer[buffer.Count - 2] == CarriageReturn)
                // strip trailing CRLF
                return encoding.GetString(buffer.Take(buffer.Count - 2).ToArray());
            else if (buffer.Count > 1 && buffer[buffer.Count - 1] == LineFeed)
                // strip trailing LF
                return encoding.GetString(buffer.Take(buffer.Count - 1).ToArray());
            else
                return encoding.GetString(buffer.ToArray());
        }

        private void SocketWriteLine(string str)
        {
            SocketWrite(Encoding.UTF8.GetBytes(str + Environment.NewLine));
        }

        private byte[] SocketRead(int length)
        {
            var receivedTotal = 0;  // how many bytes is already received
            var buffer = new byte[length];

            do
            {
                try
                {
                    var receivedBytes = _socket.Receive(buffer, receivedTotal, length - receivedTotal, SocketFlags.None);
                    if (receivedBytes > 0)
                    {
                        receivedTotal += receivedBytes;
                        continue;
                    }
                    throw new SocketException((int)SocketError.ConnectionAborted);
                }
                catch (SocketException exp)
                {
                    if (exp.SocketErrorCode == SocketError.WouldBlock ||
                        exp.SocketErrorCode == SocketError.IOPending ||
                        exp.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        // socket buffer is probably empty, wait and try again
                        Thread.Sleep(30);
                    }
                    else
                    {
                        throw;
                    }
                }
            } while (receivedTotal < length);

            return buffer;
        }

        private void SocketWrite(byte[] data)
        {
            SocketWrite(data, 0, data.Length);
        }

        private void SocketWrite(byte[] data, int offset, int length)
        {
            var totalBytesSent = 0;  // how many bytes are already sent
            var totalBytesToSend = length;

            do
            {
                try
                {
                    totalBytesSent += _socket.Send(data, offset + totalBytesSent, totalBytesToSend - totalBytesSent,
                        SocketFlags.None);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.WouldBlock ||
                        ex.SocketErrorCode == SocketError.IOPending ||
                        ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
                    {
                        // socket buffer is probably full, wait and try again
                        Thread.Sleep(30);
                    }
                    else
                        throw;  // any serious error occurr
                }
            } while (totalBytesSent < totalBytesToSend);
        }

        private Message ReceiveMessage()
        {
            throw new NotImplementedException();
        }

        private void SendMessage(Message message)
        {
            throw new NotImplementedException();
        }

        private bool TrySendMessage(Message message)
        {
            try
            {
                SendMessage(message);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void RegisterAlgorithms()
        {
            _keyExchangeAlgorithms.Add("diffie-hellman-group14-sha1", x => new DiffieHellmanGroupSha1(new DiffieHellman(2048)));
            _keyExchangeAlgorithms.Add("diffie-hellman-group1-sha1", x => new DiffieHellmanGroupSha1(new DiffieHellman(1024)));

            _publicKeyAlgorithms.Add("ssh-rsa", x => new RsaKey(x));
            _publicKeyAlgorithms.Add("ssh-dss", x => new DssKey(x));

            _encryptionAlgorithms.Add("aes128-ctr", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 128, CipherModeEx.CTR, key, vi));
            _encryptionAlgorithms.Add("aes192-ctr", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 192, CipherModeEx.CTR, key, vi));
            _encryptionAlgorithms.Add("aes256-ctr", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 256, CipherModeEx.CTR, key, vi));
            _encryptionAlgorithms.Add("aes128-cbc", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 128, CipherModeEx.CBC, key, vi));
            _encryptionAlgorithms.Add("3des-cbc", (key, vi) => new EncryptionAlgorithm(new TripleDESCryptoServiceProvider(), 192, CipherModeEx.CBC, key, vi));
            _encryptionAlgorithms.Add("aes192-cbc", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 192, CipherModeEx.CBC, key, vi));
            _encryptionAlgorithms.Add("aes256-cbc", (key, vi) => new EncryptionAlgorithm(new AesCryptoServiceProvider(), 256, CipherModeEx.CBC, key, vi));

            _hmacAlgorithms.Add("hmac-md5", x => new HmacAlgorithm(new HMACMD5(x)));
            _hmacAlgorithms.Add("hmac-sha1", x => new HmacAlgorithm(new HMACSHA1(x)));

            _compressionAlgorithms.Add("none", () => new NoCompression());
            _compressionAlgorithms.Add("zlib", () => new ZlibCompression());
        }
    }
}
