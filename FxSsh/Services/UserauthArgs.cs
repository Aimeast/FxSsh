using System;

namespace FxSsh.Services
{
    /// <summary>
    /// Payload for <see cref="UserAuthService.UserAuth"/>, raised for every
    /// authentication attempt. Carries the credentials the client submitted;
    /// the host inspects them and sets <see cref="Result"/> to accept or
    /// reject the attempt.
    /// </summary>
    public class UserAuthArgs
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "none" authentication request. <see cref="Username"/> is not
        /// populated on this path.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        public UserAuthArgs(Session session)
        {
            AuthMethod = "none";
            Session = session;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "publickey" authentication request.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        /// <param name="username">The user name requesting authentication.</param>
        /// <param name="keyAlgorithm">The client's public key algorithm name, e.g. "ssh-rsa".</param>
        /// <param name="fingerprint">The fingerprint of the client's public key, computed by the library.</param>
        /// <param name="key">The client's public key blob as sent on the wire.</param>
        public UserAuthArgs(Session session, string username, string keyAlgorithm, string fingerprint, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(keyAlgorithm);
            ArgumentNullException.ThrowIfNull(fingerprint);
            ArgumentNullException.ThrowIfNull(key);

            AuthMethod = "publickey";
            KeyAlgorithm = keyAlgorithm;
            Fingerprint = fingerprint;
            Key = key;
            Session = session;
            Username = username;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserAuthArgs"/> class
        /// for a "password" authentication request.
        /// </summary>
        /// <param name="session">The session requesting authentication.</param>
        /// <param name="username">The user name requesting authentication.</param>
        /// <param name="password">The password submitted by the client.</param>
        public UserAuthArgs(Session session, string username, string password)
        {
            ArgumentNullException.ThrowIfNull(username);
            ArgumentNullException.ThrowIfNull(password);

            AuthMethod = "password";
            Username = username;
            Password = password;
            Session = session;
        }

        /// <summary>
        /// Gets the authentication method of this attempt: "none",
        /// "password", or "publickey".
        /// </summary>
        public string AuthMethod { get; private set; }

        /// <summary>
        /// Gets the session requesting authentication.
        /// </summary>
        public Session Session { get; private set; }

        /// <summary>
        /// Gets the user name requesting authentication, or null for a
        /// "none" request.
        /// </summary>
        public string Username { get; private set; }

        /// <summary>
        /// Gets the submitted password; only populated for "password"
        /// requests.
        /// </summary>
        public string Password { get; private set; }

        /// <summary>
        /// Gets the client's public key algorithm name; only populated for
        /// "publickey" requests.
        /// </summary>
        public string KeyAlgorithm { get; private set; }

        /// <summary>
        /// Gets the fingerprint of the client's public key; only populated
        /// for "publickey" requests.
        /// </summary>
        public string Fingerprint { get; private set; }

        /// <summary>
        /// Gets the client's public key blob as sent on the wire; only
        /// populated for "publickey" requests.
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// Gets or sets a value indicating whether the host accepts the
        /// authentication attempt. Defaults to false (reject).
        /// </summary>
        public bool Result { get; set; }
    }
}
