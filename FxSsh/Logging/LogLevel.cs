namespace FxSsh.Logging
{
    /// <summary>
    /// Log severity levels. Ordered so that <c>(int)level</c> comparisons work:
    /// <c>IsEnabled(level) == (int)level >= MinLevel</c>.
    /// </summary>
    public enum LogLevel
    {
        /// <summary>Protocol-level detail: per-packet receive/send, channel data sizes.</summary>
        Trace = 0,

        /// <summary>Diagnostics and lifecycle: handshake and key-exchange progress, new keys, keepalive configuration and probe counts.</summary>
        Debug = 1,

        /// <summary>Important operational events: server listening, session accepted, key exchange complete with the negotiated algorithms, auth success, disconnection, forwarding listener binding.</summary>
        Info = 2,

        /// <summary>Recoverable anomalies: auth failures, rejected forwarding requests, unsupported requests or algorithms, sessions aborted by protocol errors.</summary>
        Warn = 3,

        /// <summary>Operation failures that need attention: SFTP request failure, reverse-forward startup failure, listener accept failure, session-fatal exceptions.</summary>
        Fail = 4,

        /// <summary>Server-level critical. Reserved for unrecoverable errors; the library itself currently logs nothing at this level.</summary>
        Critical = 5,
    }
}
