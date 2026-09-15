
namespace FxSsh.Messages
{
    /// <summary>
    /// Base class of messages belonging to the ssh-connection service
    /// (RFC 4254), such as channel open, data, window-adjust and channel
    /// request messages.
    /// </summary>
    public abstract class ConnectionServiceMessage : Message
    {
    }
}
