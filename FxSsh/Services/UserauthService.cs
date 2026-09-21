using System;
using FxSsh.Logging;
using FxSsh.Messages;
using FxSsh.Messages.UserAuth;

namespace FxSsh.Services
{
    /// <summary>
    /// Implements the "ssh-userauth" service (RFC 4252): validates "password",
    /// "publickey" and optionally "none" authentication requests by delegating
    /// the accept/reject decision to the <see cref="UserAuth"/> event, and
    /// registers the service the client asked to start (usually
    /// "ssh-connection") once authentication succeeds.
    /// </summary>
    public class UserAuthService : SshService
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthService"/> class.
        /// </summary>
        /// <param name="session">The session that instantiated the service for SSH_MSG_SERVICE_REQUEST "ssh-userauth".</param>
        public UserAuthService(Session session)
            : base(session)
        {
        }

        /// <summary>
        /// Gets or sets a value indicating whether the "none" authentication
        /// method (RFC 4252 section 5) is accepted. Disabled by default;
        /// when enabled, the <see cref="UserAuth"/> handler still decides
        /// whether the request succeeds.
        /// </summary>
        public bool EnableNoneAuth { get; set; } = false;

        /// <summary>
        /// Raised for every authentication attempt with the credentials the
        /// client presented ("password", "publickey" or "none"). The handler
        /// must set <see cref="UserAuthArgs.Result"/> to true to accept; with
        /// no handler subscribed, every attempt is rejected.
        /// </summary>
        public event EventHandler<UserAuthArgs> UserAuth;

        /// <summary>
        /// Occurs after authentication succeeds, carrying the service name the
        /// client asked to start (usually "ssh-connection").
        /// </summary>
        public event EventHandler<string> Succeed;

        /// <summary>
        /// Implements the base teardown hook; the user authentication service
        /// holds no resources, so this is a no-op.
        /// </summary>
        protected internal override void CloseService()
        {
        }

        internal void HandleMessageCore(UserAuthServiceMessage message)
        {
            ArgumentNullException.ThrowIfNull(message);

            // Compile-time dispatch replacing the former (dynamic) binder.
            // Concrete RequestMessage subclasses are matched before the
            // RequestMessage base, mirroring the old most-specific-overload
            // dynamic binding.
            switch (message)
            {
                case NoneRequestMessage m: HandleMessage(m); break;
                case PasswordRequestMessage m: HandleMessage(m); break;
                case PublicKeyRequestMessage m: HandleMessage(m); break;
                case RequestMessage m: HandleMessage(m); break;
            }
        }

        private void HandleMessage(RequestMessage message)
        {
            var username = string.IsNullOrEmpty(message.Username) ? "?" : message.Username;
            Log.Info($"Auth attempt: method={message.MethodName} user={username}.");
            switch (message.MethodName)
            {
                case "none" when EnableNoneAuth:
                    var noneMsg = Message.LoadFrom<NoneRequestMessage>(message);
                    HandleMessage(noneMsg);
                    break;
                case "publickey":
                    var keyMsg = Message.LoadFrom<PublicKeyRequestMessage>(message);
                    HandleMessage(keyMsg);
                    break;
                case "password":
                    var pswdMsg = Message.LoadFrom<PasswordRequestMessage>(message);
                    HandleMessage(pswdMsg);
                    break;
                case "hostbased":
                default:
                    Log.Debug($"Unsupported auth method: {message.MethodName}.");
                    _session.SendMessage(new FailureMessage());
                    break;
            }
        }

        private void HandleMessage(NoneRequestMessage message)
        {
            var verifed = false;
            var args = new UserAuthArgs(_session);
            if (UserAuth != null)
            {
                UserAuth(this, args);
                verifed = args.Result;
            }
            if (verifed)
            {
                Log.Info($"Auth succeeded: none, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);
                Succeed?.Invoke(this, message.ServiceName);
                _session.SendMessage(new SuccessMessage());
                return;
            }
            else
            {
                Log.Warn($"Auth failed: none, user {message.Username}.");
                _session.SendMessage(new FailureMessage());
            }
        }

        private void HandleMessage(PasswordRequestMessage message)
        {
            var verifed = false;

            var args = new UserAuthArgs(_session, message.Username, message.Password);
            if (UserAuth != null)
            {
                UserAuth(this, args);
                verifed = args.Result;
            }

            if (verifed)
            {
                Log.Info($"Auth succeeded: password, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);

                Succeed?.Invoke(this, message.ServiceName);

                _session.SendMessage(new SuccessMessage());
                return;
            }
            else
            {
                Log.Warn($"Auth failed: password, user {message.Username}.");
                _session.SendMessage(new FailureMessage());
            }
        }

        private void HandleMessage(PublicKeyRequestMessage message)
        {
            if (_session._publicKeyAlgorithms.ContainsKey(message.KeyAlgorithmName))
            {
                var verifed = false;

                var keyAlg = _session._publicKeyAlgorithms[message.KeyAlgorithmName](null);
                keyAlg.LoadKeyAndCertificatesData(message.PublicKey);

                var args = new UserAuthArgs(base._session, message.Username, message.KeyAlgorithmName, keyAlg.GetFingerprint(), message.PublicKey);
                UserAuth?.Invoke(this, args);
                verifed = args.Result;

                Log.Info($"Public key auth: user={message.Username} alg={message.KeyAlgorithmName} fp={args.Fingerprint}.");

                if (!verifed)
                {
                    Log.Warn($"Public key auth rejected by host policy: user {message.Username}.");
                    _session.SendMessage(new FailureMessage());
                    return;
                }

                if (!message.HasSignature)
                {
                    Log.Debug("Public key accepted, awaiting signature.");
                    _session.SendMessage(new PublicKeyOkMessage { KeyAlgorithmName = message.KeyAlgorithmName, PublicKey = message.PublicKey });
                    return;
                }

                var sig = keyAlg.GetSignature(message.Signature);

                // A signed request can only be verified against an established
                // session id; one arriving before key exchange is malformed
                // and is rejected instead of dereferencing a null id.
                if (_session.SessionId == null)
                {
                    Log.Warn($"Public key signature received before key exchange: user {message.Username}.");
                    _session.SendMessage(new FailureMessage());
                    return;
                }

                var bytes = new SshDataWriter(4 + _session.SessionId.Length + message.PayloadWithoutSignature.Length)
                    .WriteBinary(_session.SessionId)
                    .WriteBytes(message.PayloadWithoutSignature)
                    .ToByteArray();

                verifed = keyAlg.VerifyData(bytes, sig);

                if (!verifed)
                {
                    Log.Warn($"Public key signature verification failed: user {message.Username}.");
                    _session.SendMessage(new FailureMessage());
                    return;
                }

                Log.Info($"Auth succeeded: publickey, user {message.Username}.");
                _session.RegisterService(message.ServiceName, args);
                Succeed?.Invoke(this, message.ServiceName);
                _session.SendMessage(new SuccessMessage());
            }
            else
            {
                Log.Warn($"Unsupported key algorithm: {message.KeyAlgorithmName}.");
                _session.SendMessage(new FailureMessage());
            }
        }
    }
}
