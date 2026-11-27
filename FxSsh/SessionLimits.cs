using System;

namespace FxSsh
{
    /// <summary>
    /// Memory and concurrency limits for one <see cref="Session"/>. The
    /// values are snapshotted when the session is constructed; replacing the
    /// instance on <see cref="SshServer.Limits"/> affects only sessions
    /// accepted afterwards.
    /// </summary>
    public sealed class SessionLimits
    {
        /// <summary>
        /// Gets the maximum bytes buffered for outbound data across the whole
        /// session: framed packets waiting for the send pump plus channel
        /// backlogs waiting for peer window credit. Defaults to 64 MiB.
        /// </summary>
        public long MaximumOutboundBytes { get; init; } = 64L * 1024 * 1024;

        /// <summary>
        /// Gets the maximum bytes a single channel may buffer: the payload
        /// queued while the channel awaits OPEN_CONFIRMATION, plus one
        /// in-flight chunk of a direct send. A stalled peer is bounded
        /// session-wide by <see cref="MaximumOutboundBytes"/>. Defaults to
        /// 8 MiB.
        /// </summary>
        public int MaximumBufferedSendBytesPerChannel { get; init; } = 8 * 1024 * 1024;

        /// <summary>
        /// Gets the maximum number of simultaneously open channels per
        /// connection. Defaults to 256.
        /// </summary>
        public int MaximumChannels { get; init; } = 256;

        /// <summary>
        /// Gets the maximum number of inbound channel messages queued for the
        /// connection service before the session is disconnected. Defaults
        /// to 256.
        /// </summary>
        public int MaximumQueuedChannelMessages { get; init; } = 256;

        internal void Validate()
        {
            if (MaximumOutboundBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(MaximumOutboundBytes));
            if (MaximumBufferedSendBytesPerChannel <= 0)
                throw new ArgumentOutOfRangeException(nameof(MaximumBufferedSendBytesPerChannel));
            if (MaximumChannels <= 0)
                throw new ArgumentOutOfRangeException(nameof(MaximumChannels));
            if (MaximumQueuedChannelMessages <= 0)
                throw new ArgumentOutOfRangeException(nameof(MaximumQueuedChannelMessages));
        }
    }
}
