using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace FxSsh.Algorithms
{
    /// <summary>
    /// Hybrid post-quantum key exchange mlkem768x25519-sha256 per
    /// draft-ietf-sshm-mlkem-hybrid-kex (PQ/T hybrid of X25519 ECDH and the
    /// ML-KEM-768 key encapsulation mechanism, FIPS 203).
    ///
    /// Wire layout (all parts bare concatenation, no inner length prefixes):
    ///   C_INIT  = C_PK2 (ML-KEM-768 encapsulation key, 1184 B) || C_PK1 (X25519 pub, 32 B)
    ///   S_REPLY = S_CT2 (ML-KEM-768 ciphertext, 1088 B)       || S_PK1 (X25519 pub, 32 B)
    /// The shared secret is K = SHA256(K_PQ || K_CL), where K_PQ is the KEM
    /// shared secret and K_CL the X25519 shared secret; both are fixed 32-byte
    /// big-endian byte arrays. K is carried in the exchange hash and in key
    /// derivation as an SSH string (see <see cref="SharedSecretIsString"/>),
    /// unlike the mpint K of classical ECDH methods.
    /// </summary>
    public class MlkemX25519Kex : KexAlgorithm
    {
        private const int X25519PublicKeySize = 32;
        private const int MlKem768EncapsulationKeySize = 1184;
        private const int MlKem768CiphertextSize = 1088;
        private const int SharedSecretSize = 32;

        private readonly X25519DiffieHellman _x25519;

        // S_CT2, produced by DecryptKeyExchange and consumed by
        // CreateKeyExchange when assembling S_REPLY.
        private byte[] _serverCiphertext;

        /// <summary>
        /// Initializes a new instance of the <see cref="MlkemX25519Kex"/> class,
        /// generating the server's X25519 key pair and selecting SHA-256; the
        /// ML-KEM-768 encapsulation is performed against the client's key during
        /// <see cref="DecryptKeyExchange"/>.
        /// </summary>
        public MlkemX25519Kex()
        {
            _x25519 = X25519DiffieHellman.GenerateKey();
            _hashAlgorithm = SHA256.Create();
        }

        /// <summary>
        /// The hybrid K carries its hash output as an SSH string in the
        /// exchange hash and in key derivation (RFC 4253 section 7.2), not as
        /// the mpint used by classical ECDH methods.
        /// </summary>
        public override bool SharedSecretIsString => true;

        /// <summary>
        /// Assemble S_REPLY = S_CT2 || S_PK1. Must be called after
        /// <see cref="DecryptKeyExchange"/> has produced the ciphertext.
        /// </summary>
        public override byte[] CreateKeyExchange()
        {
            if (_serverCiphertext == null)
                throw new InvalidOperationException("DecryptKeyExchange must be called before CreateKeyExchange.");

            var serverPublicKey = _x25519.ExportPublicKey();
            var reply = new byte[_serverCiphertext.Length + serverPublicKey.Length];
            _serverCiphertext.CopyTo(reply, 0);
            serverPublicKey.CopyTo(reply, _serverCiphertext.Length);
            return reply;
        }

        /// <summary>
        /// Parse C_INIT = C_PK2 || C_PK1, encapsulate to the client's ML-KEM-768
        /// key (yielding S_CT2 and K_PQ), derive the X25519 secret K_CL, and
        /// return K = SHA256(K_PQ || K_CL) as raw 32-byte hash output.
        /// </summary>
        public override byte[] DecryptKeyExchange(byte[] exchangeData)
        {
            ArgumentNullException.ThrowIfNull(exchangeData);

            // Length check before any KEM work (draft section 2.1).
            if (exchangeData.Length != MlKem768EncapsulationKeySize + X25519PublicKeySize)
                throw new InvalidDataException("C_INIT length does not match mlkem768x25519-sha256.");

            var clientKemKey = exchangeData.AsMemory(0, MlKem768EncapsulationKeySize); // C_PK2
            var clientX25519Key = exchangeData.AsMemory(MlKem768EncapsulationKeySize, X25519PublicKeySize); // C_PK1

            // K_PQ: encapsulate to the client's ML-KEM-768 encapsulation key.
            using var kemKey = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, clientKemKey.Span);
            var ciphertext = new byte[MlKem768CiphertextSize];
            var kPq = new byte[SharedSecretSize];
            kemKey.Encapsulate(ciphertext, kPq);

            // K_CL: X25519 shared secret; reject low-order all-zero output.
            var kCl = _x25519.DeriveRawSecretAgreement(clientX25519Key.ToArray());
            if (kCl.All(b => b == 0))
                throw new CryptographicException("X25519 shared secret is all zeros.");

            // Only commit the ciphertext to the state machine after every
            // validation has passed, so a failed exchange leaves the object
            // clean and CreateKeyExchange still refuses to run.
            _serverCiphertext = ciphertext;

            // K = SHA256(K_PQ || K_CL), both fixed 32-byte arrays (draft section 2.4).
            var concat = new byte[kPq.Length + kCl.Length];
            kPq.CopyTo(concat, 0);
            kCl.CopyTo(concat, kPq.Length);
            return SHA256.HashData(concat);
        }
    }
}
