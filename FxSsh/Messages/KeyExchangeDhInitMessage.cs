namespace FxSsh.Messages
{
    public class KeyExchangeDhInitMessage : KeyExchangeXInitMessage
    {
        public byte[] E { get; private set; }

        protected override void OnLoad(SshDataReader reader)
        {
            E = reader.ReadMpint();
        }
    }
}
