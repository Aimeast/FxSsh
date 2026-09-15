using System;
using System.Collections.Generic;
using System.Text;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="Session.KeysExchanged"/>, raised when the
    /// peer's SSH_MSG_KEXINIT is received (RFC 4253 section 7.1). Exposes
    /// the algorithm name-lists the peer advertised, for inspection or
    /// logging; algorithm negotiation itself is performed by the library.
    /// </summary>
    public class KeyExchangeArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyExchangeArgs"/> class.
        /// </summary>
        /// <param name="s">The session that received the key exchange request.</param>
        public KeyExchangeArgs(Session s)
        {
            this.Session = s;
        }

        /// <summary>
        /// Gets the session that received the key exchange request.
        /// </summary>
        public Session Session { get; private set; }

        /// <summary>
        /// Gets the key exchange cookie from the peer's KEXINIT packet. The
        /// library does not populate this value, so it is always null.
        /// </summary>
        public byte[] Cookie { get; private set; }

        /// <summary>
        /// Gets or sets the key exchange algorithms advertised by the peer
        /// (KEXINIT "key_exchange_algorithms" name-list).
        /// </summary>
        public string[] KeyExchangeAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the server host key algorithms advertised by the peer
        /// (KEXINIT "server_host_key_algorithms" name-list).
        /// </summary>
        public string[] ServerHostKeyAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the encryption algorithms advertised by the peer for
        /// the client-to-server direction.
        /// </summary>
        public string[] EncryptionAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the encryption algorithms advertised by the peer for
        /// the server-to-client direction.
        /// </summary>
        public string[] EncryptionAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the MAC algorithms advertised by the peer for the
        /// client-to-server direction.
        /// </summary>
        public string[] MacAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the MAC algorithms advertised by the peer for the
        /// server-to-client direction.
        /// </summary>
        public string[] MacAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the compression algorithms advertised by the peer for
        /// the client-to-server direction.
        /// </summary>
        public string[] CompressionAlgorithmsClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the compression algorithms advertised by the peer for
        /// the server-to-client direction.
        /// </summary>
        public string[] CompressionAlgorithmsServerToClient { get; set; }

        /// <summary>
        /// Gets or sets the language tags advertised by the peer for the
        /// client-to-server direction.
        /// </summary>
        public string[] LanguagesClientToServer { get; set; }

        /// <summary>
        /// Gets or sets the language tags advertised by the peer for the
        /// server-to-client direction.
        /// </summary>
        public string[] LanguagesServerToClient { get; set; }
    }
}
