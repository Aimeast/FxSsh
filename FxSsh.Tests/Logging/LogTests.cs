using System;
using System.Collections.Generic;
using FxSsh.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace FxSsh.Tests.Logging
{
    [TestClass]
    public sealed class LogTests
    {
        private sealed class CapturingSink : ILogSink
        {
            public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

            public void Write(LogLevel level, string message, Exception? exception = null)
            {
                lock (Entries)
                {
                    Entries.Add((level, message, exception));
                }
            }
        }

        [TestCleanup]
        public void RestoreDefaults()
        {
            Log.Configure(new LogOptions());
        }

        [TestMethod]
        public void MinLevel_filters_entries()
        {
            var sink = new CapturingSink();
            Log.Configure(new LogOptions { MinLevel = LogLevel.Warn, Sink = sink });

            Log.Trace("t");
            Log.Debug("d");
            Log.Info("i");
            Log.Warn("w");
            Log.Fail("f", new InvalidOperationException("boom"));

            Assert.AreEqual(2, sink.Entries.Count);
            Assert.AreEqual(LogLevel.Warn, sink.Entries[0].Level);
            Assert.AreEqual("w", sink.Entries[0].Message);
            Assert.AreEqual(LogLevel.Fail, sink.Entries[1].Level);
            Assert.AreEqual("f", sink.Entries[1].Message);
            Assert.IsInstanceOfType(sink.Entries[1].Exception, typeof(InvalidOperationException));
        }

        [TestMethod]
        public void All_levels_are_delivered_at_trace_level()
        {
            var sink = new CapturingSink();
            Log.Configure(new LogOptions { MinLevel = LogLevel.Trace, Sink = sink });

            Log.Trace("t");
            Log.Debug("d");
            Log.Info("i");
            Log.Warn("w");
            Log.Fail("f");
            Log.Critical("c");

            Assert.AreEqual(6, sink.Entries.Count);
        }

        [TestMethod]
        public void IsEnabled_reflects_the_configured_level()
        {
            var sink = new CapturingSink();
            Log.Configure(new LogOptions { MinLevel = LogLevel.Info, Sink = sink });

            Assert.IsFalse(Log.IsEnabled(LogLevel.Trace));
            Assert.IsFalse(Log.IsEnabled(LogLevel.Debug));
            Assert.IsTrue(Log.IsEnabled(LogLevel.Info));
            Assert.IsTrue(Log.IsEnabled(LogLevel.Fail));
        }

        [TestMethod]
        public void Configure_accepts_null_options()
        {
            Log.Configure(null);
            Log.Info("still works");
        }

        [TestMethod]
        public void ConsoleLogSink_writes_entries_without_throwing()
        {
            var sink = new ConsoleLogSink();

            sink.Write(LogLevel.Info, "console message");
            sink.Write(LogLevel.Fail, "console failure", new InvalidOperationException("details"));
        }

        [TestMethod]
        public void NullLogSink_discards_entries()
        {
            var sink = new NullLogSink();

            sink.Write(LogLevel.Trace, "discarded");
            sink.Write(LogLevel.Critical, "discarded", new Exception("x"));
        }

        [TestMethod]
        public void LogLevelExtensions_map_every_level()
        {
            // internal helper - reachable through the friend assembly.
            var extensionsType = typeof(LogOptions).Assembly.GetType("FxSsh.Logging.LogLevelExtensions")!;

            var shortNames = extensionsType.GetMethod("ToShortName", [typeof(LogLevel)])!;
            Assert.AreEqual("trce", shortNames.Invoke(null, [LogLevel.Trace]));
            Assert.AreEqual("dbug", shortNames.Invoke(null, [LogLevel.Debug]));
            Assert.AreEqual("info", shortNames.Invoke(null, [LogLevel.Info]));
            Assert.AreEqual("warn", shortNames.Invoke(null, [LogLevel.Warn]));
            Assert.AreEqual("fail", shortNames.Invoke(null, [LogLevel.Fail]));
            Assert.AreEqual("crit", shortNames.Invoke(null, [LogLevel.Critical]));
            Assert.AreEqual("info", shortNames.Invoke(null, [(LogLevel)99]));

            var toColor = extensionsType.GetMethod("ToColor", [typeof(LogLevel)])!;
            Assert.IsNotNull(toColor.Invoke(null, [LogLevel.Trace]));
            Assert.IsNotNull(toColor.Invoke(null, [LogLevel.Critical]));
        }
    }
}
