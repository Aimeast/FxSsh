using System.Text;

namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// SSH_MSG_CHANNEL_REQUEST "exit-signal" per RFC 4254 section 6.10.
    /// Sent instead of exit-status when the process was terminated by a signal.
    /// </summary>
    public class ExitSignalMessage : ChannelRequestMessage
    {
        /// <summary>
        /// Signal name WITHOUT the "SIG" prefix (e.g. "TERM", "KILL", "SEGV"),
        /// per RFC 4254 section 6.10.
        /// </summary>
        public string SignalName { get; set; }

        /// <summary>
        /// True if the process terminated due to a core dump.
        /// </summary>
        public bool CoreDumped { get; set; }

        /// <summary>
        /// Human-readable explanation (may be empty).
        /// </summary>
        public string ErrorMessage { get; set; }

        /// <summary>
        /// Language tag per RFC 3066 (e.g. "en").
        /// </summary>
        public string Language { get; set; } = "en";

        /// <summary>Writes the exit-signal request into the outgoing packet; the request is always sent without asking for a reply.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            RequestType = "exit-signal";
            WantReply = false;

            base.OnGetPacket(writer);

            writer.Write(SignalName ?? string.Empty, Encoding.ASCII);
            writer.Write(CoreDumped);
            writer.Write(ErrorMessage ?? string.Empty, Encoding.UTF8);
            writer.Write(Language ?? "en", Encoding.ASCII);
        }
    }
}
