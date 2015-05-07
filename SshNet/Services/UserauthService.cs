using SshNet.Messages;
using SshNet.Messages.Userauth;
using System;

namespace SshNet.Services
{
    public class UserauthService : SshService
    {
        public UserauthService(Session session)
            : base(session)
        {
        }

        public event EventHandler<UserauthArgs> Userauth;

        public event EventHandler<string> Succeed;

        internal void HandleMessageCore(UserauthServiceMessage message)
        {
            HandleMessage((dynamic)message);
        }

        private void HandleMessage(RequestMessage message)
        {
            switch (message.MethodName)
            {
                case "publickey":
                    var msg = new PublicKeyRequestMessage();
                    msg.Load(message.RawBytes);
                    HandleMessage(msg);
                    break;
                case "password":
                case "hostbased":
                case "none":
                default:
                    _session.SendMessage(new FailureMessage());
                    break;
            }
        }

        private void HandleMessage(PublicKeyRequestMessage message)
        {
            if (Session._publicKeyAlgorithms.ContainsKey(message.KeyAlgorithmName))
            {
                if (!message.HasSignature)
                {
                    _session.SendMessage(new PublicKeyOkMessage { KeyAlgorithmName = message.KeyAlgorithmName, PublicKey = message.PublicKey });
                    return;
                }

                var keyAlg = Session._publicKeyAlgorithms[message.KeyAlgorithmName](null);
                keyAlg.LoadKeyAndCertificatesData(message.PublicKey);

                var sig = keyAlg.GetSignature(message.Signature);
                var verifed = false;

                using (var worker = new SshDataWorker())
                {
                    worker.WriteBinary(_session.SessionId);
                    worker.Write(message.PayloadWithoutSignature);

                    verifed = keyAlg.VerifyData(worker.ToArray(), sig);
                }

                if (verifed && Userauth != null)
                {
                    var args = new UserauthArgs(message.KeyAlgorithmName, keyAlg.GetFingerprint(), message.PublicKey);
                    Userauth(this, args);
                    verifed = args.Result;
                }

                if (verifed)
                {
                    _session.RegisterService(message.ServiceName, true);
                    if (Succeed != null)
                        Succeed(this, message.ServiceName);
                    _session.SendMessage(new SuccessMessage());
                    return;
                }
                else
                {
                    _session.SendMessage(new FailureMessage());
                    throw new SshConnectionException("Authentication fail.", DisconnectReason.NoMoreAuthMethodsAvailable);
                }
            }
            _session.SendMessage(new FailureMessage());
        }
    }
}
