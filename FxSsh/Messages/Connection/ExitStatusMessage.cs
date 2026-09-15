
namespace FxSsh.Messages.Connection
{
    /// <summary>
    /// Represents the SSH_MSG_CHANNEL_REQUEST "exit-status" request
    /// (RFC 4254 section 6.10), which reports the exit status of a command
    /// or shell that has finished on the channel.
    /// </summary>
    public class ExitStatusMessage : ChannelRequestMessage
    {
        /// <summary>Gets or sets the exit status value returned by the remote command or shell.</summary>
        public uint ExitStatus { get; set; }

        /// <summary>Writes the exit-status request into the outgoing packet; the request is always sent without asking for a reply.</summary>
        /// <param name="writer">The writer used to serialize the message payload.</param>
        protected override void OnGetPacket(SshDataWriter writer)
        {
            RequestType = "exit-status";
            WantReply = false;

            base.OnGetPacket(writer);

            writer.Write(ExitStatus);
        }
    }
}
