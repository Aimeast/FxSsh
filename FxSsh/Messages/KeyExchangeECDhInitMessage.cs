namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_KEX_ECDH_INIT (30) message of an ECDH key
    /// exchange (RFC 5656 section 4), carrying the client's ephemeral public
    /// key.
    /// </summary>
    public class KeyExchangeECDhInitMessage : KeyExchangeXInitMessage
    {
        /// <summary>
        /// Gets the client's ephemeral ECDH public key Q_C, encoded as an
        /// octet string.
        /// </summary>
        public byte[] Q { get; private set; }

        /// <summary>
        /// Loads the client's ephemeral public key from the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            Q = reader.ReadBinary();
        }
    }
}
