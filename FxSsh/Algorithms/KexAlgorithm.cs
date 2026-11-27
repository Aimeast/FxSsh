using System;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Represents the base class for SSH key-exchange algorithms, which produce
    /// the server's key-exchange data and the shared secret K combined with the
    /// exchange hash H to derive session keys (RFC 4253 section 7.2).
    /// </summary>
    public abstract class KexAlgorithm : IDisposable
    {
        /// <summary>
        /// The hash algorithm used to compute the exchange hash H and to derive
        /// the session keys (RFC 4253 section 7.2).
        /// </summary>
        protected HashAlgorithm _hashAlgorithm;
        private bool _disposed;

        /// <summary>
        /// When overridden in a derived class, creates the server's key-exchange
        /// data for the negotiated method.
        /// </summary>
        /// <returns>The raw key-exchange data, not SSH-framed.</returns>
        public abstract byte[] CreateKeyExchange();

        /// <summary>
        /// When overridden in a derived class, derives the shared secret K from
        /// the key-exchange data received from the client.
        /// </summary>
        /// <param name="exchangeData">The raw key-exchange data received from the client.</param>
        /// <returns>The raw shared secret K, not SSH-framed.</returns>
        public abstract byte[] DecryptKeyExchange(byte[] exchangeData);

        /// <summary>
        /// True when the shared secret K enters the exchange hash and the key
        /// derivation (RFC 4253 section 7.2) as an SSH string (hybrid PQ/T
        /// methods, e.g. mlkem768x25519-sha256), instead of the mpint used by
        /// classical ECDH/DH methods.
        /// </summary>
        public virtual bool SharedSecretIsString => false;

        /// <summary>
        /// Computes the hash of the specified input using <see cref="_hashAlgorithm"/>.
        /// </summary>
        /// <param name="input">The data to hash.</param>
        /// <returns>The computed hash.</returns>
        public byte[] ComputeHash(byte[] input)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(input);

            return _hashAlgorithm.ComputeHash(input);
        }

        /// <summary>
        /// Releases the ephemeral key-exchange resources: the hash instance
        /// and any asymmetric key pair held by the derived class. Session
        /// disposes the algorithm after the exchange hash and key derivation
        /// have consumed it.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the resources held by the derived key-exchange method.
        /// </summary>
        /// <param name="disposing">True when called from <see cref="Dispose()"/>.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
                _hashAlgorithm?.Dispose();
        }
    }
}
