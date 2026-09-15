#nullable enable
using System;

namespace FxSsh.Logging
{
    /// <summary>
    /// Simple console log sink for debugging. Writes one line per entry as
    /// <c>yy-MM-dd HH:mm:ss LEVEL message</c> (optional exception appended).
    /// Only the 4-letter LEVEL token is color-coded by severity; the timestamp
    /// and message use the console's default color. Timestamp precision is
    /// seconds; attach a custom <see cref="ILogSink"/> for production
    /// formatting or async buffering.
    /// </summary>
    public sealed class ConsoleLogSink : ILogSink
    {
        /// <summary>
        /// Writes one entry to the standard output stream in the
        /// <c>yy-MM-dd HH:mm:ss LEVEL message</c> format, color-coding the
        /// level token by severity and appending the exception text on a new
        /// line when present.
        /// </summary>
        /// <param name="level">Severity of the entry; selects the level text and color.</param>
        /// <param name="message">Pre-formatted message. Never null.</param>
        /// <param name="exception">Optional exception to append below the message.</param>
        public void Write(LogLevel level, string message, Exception? exception = null)
        {
            var timestamp = DateTime.Now.ToString("yy-MM-dd HH:mm:ss");
            var levelText = level.ToShortName();
            var previous = Console.ForegroundColor;
            try
            {
                Console.Write($"{timestamp} ");
                Console.ForegroundColor = level.ToColor();
                Console.Write($"{levelText} ");
            }
            finally
            {
                Console.ForegroundColor = previous;
            }

            Console.WriteLine(exception == null ? message : message + Environment.NewLine + exception);
        }
    }

    internal static class LogLevelExtensions
    {
        public static string ToShortName(this LogLevel level) => level switch
        {
            LogLevel.Trace => "trce",
            LogLevel.Debug => "dbug",
            LogLevel.Info => "info",
            LogLevel.Warn => "warn",
            LogLevel.Fail => "fail",
            LogLevel.Critical => "crit",
            _ => "info",
        };

        public static ConsoleColor ToColor(this LogLevel level) => level switch
        {
            LogLevel.Trace => ConsoleColor.DarkGray,
            LogLevel.Debug => ConsoleColor.Cyan,
            LogLevel.Info => ConsoleColor.Green,
            LogLevel.Warn => ConsoleColor.Yellow,
            LogLevel.Fail => ConsoleColor.Red,
            LogLevel.Critical => ConsoleColor.DarkRed,
            _ => ConsoleColor.Gray,
        };
    }
}
