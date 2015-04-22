
namespace SshNet.Messages
{
    public abstract class Message
    {
        public abstract void Load(byte[] bytes);
        public abstract byte[] GetPacket();
    }
}
