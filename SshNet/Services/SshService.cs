
namespace SshNet.Services
{
    public abstract class SshService
    {
        protected readonly Session _session;

        public SshService(Session session)
        {
            _session = session;
        }
    }
}
