#nullable enable
namespace FxSsh.Logging
{
    /// <summary>
    /// No-op log sink. The default destination - the library is completely
    /// silent (and zero cost) until the host configures a real sink.
    /// </summary>
    public sealed class NullLogSink : ILogSink
    {
        /// <summary>
        /// Discards the entry. All parameters are ignored and no output is
        /// ever produced.
        /// </summary>
        /// <param name="level">Severity of the entry; ignored.</param>
        /// <param name="message">Message to discard.</param>
        /// <param name="exception">Optional exception to discard.</param>
        public void Write(LogLevel level, string message, System.Exception? exception = null)
        {
            // Intentionally does nothing.
        }
    }
}
