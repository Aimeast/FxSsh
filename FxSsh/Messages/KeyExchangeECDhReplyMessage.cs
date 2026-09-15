namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_KEX_ECDH_REPLY (31) message of an ECDH key
    /// exchange (RFC 5656 section 4), carrying the server's host key, its own
    /// ephemeral public key and the signature over the exchange hash.
    /// </summary>
    public class KeyExchangeECDhReplyMessage : KeyExchangeXReplyMessage
    {
        /// <summary>
        /// Gets or sets the server's public host key blob (K_S).
        /// </summary>
        public byte[] HostKey { get; set; }

        /// <summary>
        /// Gets or sets the server's ephemeral ECDH public key Q_S, encoded as
        /// an octet string.
        /// </summary>
        public byte[] Q { get; set; }

        /// <summary>
        /// Gets or sets the signature over the exchange hash H, created with
        /// the server's host key.
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Writes the host key blob, the server's public key and the signature
        /// to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.WriteBinary(HostKey);
            writer.WriteBinary(Q);
            writer.WriteBinary(Signature);
        }
    }
}
