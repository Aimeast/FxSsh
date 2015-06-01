using System.Diagnostics.Contracts;

namespace SshNet.Services
{
    public abstract class SshService
    {
        protected internal readonly Session _session;

        public SshService(Session session)
        {
            Contract.Requires(session != null);

            _session = session;
        }
    }
}
