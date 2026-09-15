using System;
using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents an SSH_MSG_USERAUTH_REQUEST using the "publickey" method
    /// (RFC 4252 section 7). With no signature it is a query asking whether
    /// the key would be accepted (answered by <see cref="PublicKeyOkMessage"/>);
    /// with a signature it is an authentication attempt.
    /// </summary>
    public class PublicKeyRequestMessage : RequestMessage
    {
        /// <summary>
        /// Gets a value indicating whether the request carries a signature,
        /// i.e. is an authentication attempt rather than an algorithm/key
        /// query.
        /// </summary>
        public bool HasSignature { get; private set; }

        /// <summary>
        /// Gets the public key algorithm name, e.g. "ssh-rsa" or "ssh-ed25519".
        /// </summary>
        public string KeyAlgorithmName { get; private set; }

        /// <summary>
        /// Gets the client's public key blob.
        /// </summary>
        public byte[] PublicKey { get; private set; }

        /// <summary>
        /// Gets the signature over the authentication request data; empty when
        /// the request is only a query (<see cref="HasSignature"/> is false).
        /// </summary>
        public ReadOnlyMemory<byte> Signature { get; private set; }

        /// <summary>
        /// Gets the raw request bytes with the trailing signature field
        /// stripped: the message number followed by the request fields up to
        /// the public key blob. The caller prepends the session id to this
        /// value to obtain the exact blob the client signed (RFC 4252
        /// section 7).
        /// </summary>
        public ReadOnlyMemory<byte> PayloadWithoutSignature { get; private set; }

        /// <summary>
        /// Loads the base request fields, verifies the method name and reads
        /// the has-signature flag, algorithm name, public key blob and, when
        /// present, the signature.
        /// </summary>
        /// <exception cref="ArgumentException">The request uses a method name other than "publickey".</exception>
        protected override void OnLoad(SshDataReader reader)
        {
            base.OnLoad(reader);

            if (MethodName != "publickey")
                throw new ArgumentException(string.Format("Method name {0} is not valid.", MethodName));

            HasSignature = reader.ReadBoolean();
            KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
            PublicKey = reader.ReadBinary();

            if (HasSignature)
            {
                Signature = reader.ReadBinaryAsMemory();
                // Strip the trailing `string signature` (4-byte length prefix +
                // content) from RawBytes. The signed data is session_id ||
                // (type .. public key blob) -- exactly what the peer signed.
                PayloadWithoutSignature = RawBytes[..(RawBytes.Length - Signature.Length - 4)];
            }
        }
    }
}
