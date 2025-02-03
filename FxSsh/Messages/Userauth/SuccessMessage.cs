namespace FxSsh.Messages.UserAuth
{
    [Message("SSH_MSG_USERAUTH_SUCCESS", MessageNumber)]
    public class SuccessMessage : UserAuthServiceMessage
    {
        private const byte MessageNumber = 52;

        public override byte MessageType { get { return MessageNumber; } }

        protected override void OnGetPacket(SshDataWriter writer)
        {
        }
    }
}
