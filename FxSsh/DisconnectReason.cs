using System.ComponentModel;

namespace FxSsh
{
    /// <summary>
    /// Specifies the reason codes carried by SSH_MSG_DISCONNECT
    /// (RFC 4253 section 11.1) when a party terminates the connection.
    /// </summary>
    public enum DisconnectReason
    {
        /// <summary>Placeholder for reason code 0, which the protocol never sends.</summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        None = 0, // Not used by protocol
        /// <summary>The remote host is not permitted to connect to the server (SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT).</summary>
        HostNotAllowedToConnect = 1,
        /// <summary>A protocol-level error was detected, such as a malformed or invalid message (SSH_DISCONNECT_PROTOCOL_ERROR).</summary>
        ProtocolError = 2,
        /// <summary>Key exchange failed, leaving the parties unable to establish a secure session (SSH_DISCONNECT_KEY_EXCHANGE_FAILED).</summary>
        KeyExchangeFailed = 3,
        /// <summary>Reserved reason code; not currently defined or used (SSH_DISCONNECT_RESERVED).</summary>
        Reserved = 4,
        /// <summary>A message failed its message authentication code integrity check (SSH_DISCONNECT_MAC_ERROR).</summary>
        MacError = 5,
        /// <summary>Compression or decompression of a packet failed (SSH_DISCONNECT_COMPRESSION_ERROR).</summary>
        CompressionError = 6,
        /// <summary>The requested service is not available or not supported (SSH_DISCONNECT_SERVICE_NOT_AVAILABLE).</summary>
        ServiceNotAvailable = 7,
        /// <summary>The remote protocol version is not supported (SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED).</summary>
        ProtocolVersionNotSupported = 8,
        /// <summary>The host key could not be verified because it is unknown or invalid (SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE).</summary>
        HostKeyNotVerifiable = 9,
        /// <summary>The connection was lost or closed unexpectedly (SSH_DISCONNECT_CONNECTION_LOST).</summary>
        ConnectionLost = 10,
        /// <summary>The application terminated the connection explicitly (SSH_DISCONNECT_BY_APPLICATION).</summary>
        ByApplication = 11,
        /// <summary>Too many simultaneous connections; the server refuses additional ones (SSH_DISCONNECT_TOO_MANY_CONNECTIONS).</summary>
        TooManyConnections = 12,
        /// <summary>Authentication was cancelled by the user (SSH_DISCONNECT_AUTH_CANCELLED_BY_USER).</summary>
        AuthCancelledByUser = 13,
        /// <summary>No further authentication methods are available (SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE).</summary>
        NoMoreAuthMethodsAvailable = 14,
        /// <summary>The supplied user name is not legal or not allowed on the server (SSH_DISCONNECT_ILLEGAL_USER_NAME).</summary>
        IllegalUserName = 15
    }
}
