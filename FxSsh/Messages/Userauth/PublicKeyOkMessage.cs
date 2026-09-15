using System.Text;

namespace FxSsh.Messages.UserAuth
{
    /// <summary>
    /// Represents the SSH_MSG_USERAUTH_PK_OK (60) message (RFC 4252 section 7).
    /// Sent in reply to a signature-less publickey request to confirm that the
    /// offered algorithm and key would be accepted, so the client can proceed
    /// with signing.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_PK_OK", MessageNumber)]
    public class PublicKeyOkMessage : UserAuthServiceMessage
    {
        internal const byte MessageNumber = 60;

        /// <summary>
        /// Gets or sets the public key algorithm name accepted by the server.
        /// </summary>
        public string KeyAlgorithmName { get; set; }

        /// <summary>
        /// Gets or sets the accepted public key blob.
        /// </summary>
        public byte[] PublicKey { get; set; }

        /// <summary>
        /// Gets the SSH message number for SSH_MSG_USERAUTH_PK_OK (60).
        /// </summary>
        public override byte MessageType { get { return MessageNumber; } }

        /// <summary>
        /// Writes the algorithm name and the public key blob to the payload.
        /// </summary>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            writer.Write(KeyAlgorithmName, Encoding.ASCII);
            writer.WriteBinary(PublicKey);
        }
    }
}
