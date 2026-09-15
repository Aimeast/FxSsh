namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_KEXDH_REPLY (31) message of a
    /// diffie-hellman-group* key exchange (RFC 4253 section 8), carrying the
    /// server's host key, its own Diffie-Hellman public value and the
    /// signature over the exchange hash.
    /// </summary>
    public class KeyExchangeDhReplyMessage : KeyExchangeXReplyMessage
    {
        /// <summary>
        /// Gets or sets the server's public host key blob (K_S).
        /// </summary>
        public byte[] HostKey { get; set; }

        /// <summary>
        /// Gets or sets the server's Diffie-Hellman public value f = g^y mod p,
        /// encoded as an mpint.
        /// </summary>
        public byte[] F { get; set; }

        /// <summary>
        /// Gets or sets the signature over the exchange hash H, created with
        /// the server's host key.
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Writes the host key blob, the server's public value and the
        /// signature to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.WriteBinary(HostKey);
            writer.WriteMpint(F);
            writer.WriteBinary(Signature);
        }
    }
}
