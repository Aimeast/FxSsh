#nullable enable
using System;
using System.Runtime.CompilerServices;
using System.Threading;

namespace FxSsh.Logging
{
    /// <summary>
    /// Static log facade - the single entry point for all library logging.
    ///
    /// Zero-dependency and silent by default: until <see cref="Configure"/> is
    /// called, all methods are no-ops backed by <see cref="NullLogSink"/>.
    /// The <see cref="IsEnabled"/> gate is a single volatile read + branch, so
    /// hot paths pay ~nothing when a level is disabled.
    /// </summary>
    public static class Log
    {
        private static LogOptions _options = new();
        private static int _minLevel = (int)LogLevel.Info;

        /// <summary>
        /// Configure logging process-wide. Idempotent and thread-safe; call once
        /// at startup. Passing null resets to the silent default.
        /// </summary>
        public static void Configure(LogOptions? options)
        {
            options ??= new LogOptions();
            Volatile.Write(ref _options, options);

            Volatile.Write(ref _minLevel, (int)options.MinLevel);
        }

        /// <summary>
        /// Fast level gate for hot paths. Call this before constructing the
        /// log message (string interpolation/concatenation is only done when
        /// the level is enabled).
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsEnabled(LogLevel level)
            => (int)level >= Volatile.Read(ref _minLevel);

        /// <summary>
        /// Writes a protocol-level detail entry (per-packet receive/send,
        /// channel data sizes) at <see cref="LogLevel.Trace"/>. No-op unless
        /// the level passes <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        public static void Trace(in string message) => Write(LogLevel.Trace, message, null);

        /// <summary>
        /// Writes a diagnostics/lifecycle entry (handshake and key-exchange
        /// progress, new keys, keepalive probes) at <see cref="LogLevel.Debug"/>.
        /// No-op unless the level passes <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        public static void Debug(in string message) => Write(LogLevel.Debug, message, null);

        /// <summary>
        /// Writes an important operational entry (session accepted, key exchange
        /// complete, auth success, listener binding) at
        /// <see cref="LogLevel.Info"/>. No-op unless the level passes
        /// <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        public static void Info(in string message) => Write(LogLevel.Info, message, null);

        /// <summary>
        /// Writes a recoverable anomaly (auth failure, rejected request,
        /// minor protocol violation) at <see cref="LogLevel.Warn"/>. No-op
        /// unless the level passes <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        public static void Warn(in string message) => Write(LogLevel.Warn, message, null);

        /// <summary>
        /// Writes a fault that needs attention (SFTP request failure, reverse-
        /// forward startup failure, listener accept failure, session-fatal
        /// exception) at <see cref="LogLevel.Fail"/>. No-op unless the level passes
        /// <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        /// <param name="exception">Optional exception to attach to the entry.</param>
        public static void Fail(in string message, Exception? exception = null) => Write(LogLevel.Fail, message, exception);

        /// <summary>
        /// Writes a server-level critical entry (reserved for unrecoverable
        /// errors; the library currently logs nothing at this level) at
        /// <see cref="LogLevel.Critical"/>. No-op unless the level passes
        /// <see cref="IsEnabled"/>.
        /// </summary>
        /// <param name="message">Pre-formatted message to write.</param>
        /// <param name="exception">Optional exception to attach to the entry.</param>
        public static void Critical(in string message, Exception? exception = null) => Write(LogLevel.Critical, message, exception);

        private static void Write(LogLevel level, in string message, Exception? exception)
        {
            if (!IsEnabled(level))
                return;

            try
            {
                Volatile.Read(ref _options).Sink.Write(level, message, exception);
            }
            catch
            {
                // A misbehaving sink must never take the server down.
            }
        }
    }
}
