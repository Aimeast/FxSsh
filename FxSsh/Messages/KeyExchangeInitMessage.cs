using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_KEXINIT (20) message (RFC 4253 section 7.1).
    /// Both sides send it as the first packet of key exchange to advertise
    /// the algorithm name-lists they support and to exchange the random
    /// cookies mixed into the exchange hash.
    /// </summary>
    [Message("SSH_MSG_KEXINIT", MessageNumber)]
    public class KeyExchangeInitMessage : Message
    {
        internal const byte MessageNumber = 20;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyExchangeInitMessage"/>
        /// class with a fresh random 16-byte cookie.
        /// </summary>
        public KeyExchangeInitMessage()
        {
            Cookie = RandomNumberGenerator.GetBytes(16);
        }

        /// <summary>
        /// Gets the 16-byte random cookie mixed into the exchange hash.
        /// </summary>
        public byte[] Cookie { get; private set; }

        /// <summary>
        /// Gets or sets the kex_algorithms name-list: the supported key
        /// exchange methods, which may include the RFC 8308 extension markers
        /// "ext-info-c" / "ext-info-s".
        /// </summary>
        public string[] KeyExchangeAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the server_host_key_algorithms name-list: the host key
        /// algorithms the sender accepts.
        /// </summary>
        public string[] ServerHostKeyAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the encryption_algorithms_client_to_server name-list.
        /// </summary>
        public string[] EncryptionAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the encryption_algorithms_server_to_client name-list.
        /// </summary>
        public string[] EncryptionAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the mac_algorithms_client_to_server name-list; unused
        /// when an AEAD cipher is negotiated.
        /// </summary>
        public string[] MacAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the mac_algorithms_server_to_client name-list; unused
        /// when an AEAD cipher is negotiated.
        /// </summary>
        public string[] MacAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the compression_algorithms_client_to_server name-list.
        /// </summary>
        public string[] CompressionAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the compression_algorithms_server_to_client name-list.
        /// </summary>
        public string[] CompressionAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the languages_client_to_server name-list of language
        /// tags; informational only.
        /// </summary>
        public string[] LanguagesClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the languages_server_to_client name-list of language
        /// tags; informational only.
        /// </summary>
        public string[] LanguagesServerToClient { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the sender has sent a
        /// guessed key exchange packet immediately after this message
        /// (RFC 4253 section 7.1). The receiver must ignore the guessed packet
        /// unless its guess of the key exchange and host key algorithms
        /// matches the receiver's own choice.
        /// </summary>
        public bool FirstKexPacketFollows { get; set; }

        /// <summary>
        /// Gets or sets the reserved field, which must be zero per RFC 4253
        /// section 7.1.
        /// </summary>
        public uint Reserved { get; set; }

        /// <summary>
        /// The RFC 8308 extension markers ("ext-info-c" / "ext-info-s") found
        /// in the peer's kex_algorithms name-list, populated when a received
        /// KEXINIT is parsed. Outbound KEXINITs advertise extensions by
        /// including "ext-info-s" in <see cref="KeyExchangeAlgorithms"/>
        /// directly.
        /// </summary>
        public HashSet<string> PeerExtensions { get; private set; } = [];

        /// <summary>
        /// Extension names to include in the sent KEXINIT. Not read by the
        /// library itself - the send path advertises "ext-info-s" by listing
        /// it in <see cref="KeyExchangeAlgorithms"/> - but available for
        /// callers that build KEXINITs by hand.
        /// </summary>
        public HashSet<string> ExtensionNames { get; set; } = [];

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_KEXINIT (20).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Loads the cookie, the algorithm and language name-lists, the guess
        /// flag and the reserved field, and collects the RFC 8308 ext-info
        /// markers found in kex_algorithms into <see cref="PeerExtensions"/>.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            Cookie = reader.ReadBytes(16);
            KeyExchangeAlgorithms = reader.ReadString(Encoding.ASCII).Split(',');
            ServerHostKeyAlgorithms = reader.ReadString(Encoding.ASCII).Split(',');
            EncryptionAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            EncryptionAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            MacAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            MacAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            CompressionAlgorithmsClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            CompressionAlgorithmsServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            LanguagesClientToServer = reader.ReadString(Encoding.ASCII).Split(',');
            LanguagesServerToClient = reader.ReadString(Encoding.ASCII).Split(',');
            FirstKexPacketFollows = reader.ReadBoolean();
            Reserved = reader.ReadUInt32();

            // RFC 4253 section 4: reserved is the last field of the KEXINIT
            // payload. Per RFC 8308, the "ext-info-c" / "ext-info-s" extension
            // markers are advertised inside the kex_algorithms name-list (NOT
            // in a trailing name-list after reserved). OpenSSH also appends
            // "kex-strict-c-v00@openssh.com" to the same list. We therefore
            // detect extension support from KeyExchangeAlgorithms, and ignore
            // any trailing bytes after reserved (some clients append a stray
            // zero byte; RFC 4253 treats the payload as ending at reserved).
            PeerExtensions = [];
            foreach (var kex in KeyExchangeAlgorithms)
            {
                if (kex == "ext-info-c" || kex == "ext-info-s")
                    PeerExtensions.Add(kex);
            }
        }

        /// <summary>
        /// Writes the cookie, the algorithm and language name-lists, the guess
        /// flag and the reserved field.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.WriteBytes(Cookie);
            writer.Write(string.Join(",", KeyExchangeAlgorithms), Encoding.ASCII);
            writer.Write(string.Join(",", ServerHostKeyAlgorithms), Encoding.ASCII);
            writer.Write(string.Join(",", EncryptionAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", EncryptionAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", MacAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", MacAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", CompressionAlgorithmsClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", CompressionAlgorithmsServerToClient), Encoding.ASCII);
            writer.Write(string.Join(",", LanguagesClientToServer), Encoding.ASCII);
            writer.Write(string.Join(",", LanguagesServerToClient), Encoding.ASCII);
            writer.Write(FirstKexPacketFollows);
            writer.Write(Reserved);

            // RFC 8308: ext-info-s is advertised inside the kex_algorithms
            // name-list (NOT as a trailing field after reserved). It is
            // already included via KeyExchangeAlgorithms by the caller.
        }
    }
}
