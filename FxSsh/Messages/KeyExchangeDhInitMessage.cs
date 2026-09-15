using System;

namespace FxSsh.Messages
{
    /// <summary>
    /// Represents the SSH_MSG_KEXDH_INIT (30) message of a
    /// diffie-hellman-group* key exchange (RFC 4253 section 8), carrying the
    /// client's ephemeral Diffie-Hellman public value.
    /// </summary>
    public class KeyExchangeDhInitMessage : KeyExchangeXInitMessage
    {
        /// <summary>
        /// Gets the client's Diffie-Hellman public value e = g^x mod p,
        /// encoded as an mpint.
        /// </summary>
        public byte[] E { get; private set; }

        /// <summary>
        /// Loads the client's Diffie-Hellman public value from the payload.
        /// </summary>
        protected override void OnLoad(SshDataReader reader)
        {
            E = reader.ReadMpint();
        }
    }
}
