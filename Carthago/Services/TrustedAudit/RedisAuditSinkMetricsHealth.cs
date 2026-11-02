// SPDX-License-Identifier: MIT
// R437 Redis Software audit_sink_* metrics gate — SOURCE CANDIDATE — UNVERIFIED.
using System;
using System.Collections.Generic;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Operator-supplied aggregate Redis Software audit_sink_* metric values.
    /// The metrics transport, credentials, and scrape authenticity MUST be
    /// established by the operator; this model is not a verified audit receipt.
    /// All counters are Redis Software counters, never guessed from TCP traffic.
    /// </summary>
    public sealed record RedisAuditSinkMetricsSnapshot(
        DateTimeOffset ScrapedAtUtc,
        long SentMessages,
        long DroppedMessages,
        long DisconnectLossEvents,
        long ReconnectAttemptsExhausted,
        long PendingBytes);

    public enum RedisAuditSinkHealthStatus
    {
        InvalidSourceOrSnapshot,
        StaleOrNonUtcSample,
        BaselineOnly,
        NoObservedLossDelta,
        PendingBacklog,
        LossCounterIncrease,
        CounterResetOrStaleOrder,
        PreviouslyCompromised,
        TrackingCapacityExceeded
    }

    /// <summary>
    /// This reports changes between two externally supplied metric samples,
    /// never proof of no loss: Redis Software delivery is best effort, and
    /// audit_sink_sent_messages does not prove remote consumption.
    /// </summary>
    public sealed record RedisAuditSinkHealthAssessment(
        RedisAuditSinkHealthStatus Status,
        string Diagnostic)
    {
        public bool AuditDeliveryAuthenticated => false;
        public bool CompleteCommandAuditProven => false;
        public bool AlertPermitted => false;
    }

    /// <summary>
    /// Fixed-memory, per-operator-provisioned Redis source aggregate metric
    /// monitor. Loss counter increase, counter reset and out-of-order samples
    /// poison the source until explicit operator review; a reconnect never
    /// silently clears earlier audit loss.
    /// </summary>
    public sealed class RedisAuditSinkMetricsHealthMonitor
    {
        private const int MaxSources = 64;
        private static readonly TimeSpan MaxSampleAge = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan MaxFutureSkew = TimeSpan.FromSeconds(30);
        private readonly object _gate = new();
        private readonly Dictionary<string, (RedisAuditSinkMetricsSnapshot Value,
            bool Compromised)> _sources = new(StringComparer.Ordinal);

        public RedisAuditSinkHealthAssessment Observe(
            string? operatorSourceId,
            RedisAuditSinkMetricsSnapshot? sample,
            DateTimeOffset receivedUtc)
        {
            if (!ValidSourceId(operatorSourceId) || sample == null
                || sample.SentMessages < 0 || sample.DroppedMessages < 0
                || sample.DisconnectLossEvents < 0
                || sample.ReconnectAttemptsExhausted < 0
                || sample.PendingBytes < 0)
                return Assess(RedisAuditSinkHealthStatus.InvalidSourceOrSnapshot,
                    "R437_AUDIT_METRICS_INVALID");

            if (receivedUtc.Offset != TimeSpan.Zero
                || sample.ScrapedAtUtc.Offset != TimeSpan.Zero
                || sample.ScrapedAtUtc == default
                || receivedUtc - sample.ScrapedAtUtc > MaxSampleAge
                || sample.ScrapedAtUtc - receivedUtc > MaxFutureSkew)
                return Assess(RedisAuditSinkHealthStatus.StaleOrNonUtcSample,
                    "R437_AUDIT_METRICS_STALE_OR_NONUTC");

            lock (_gate)
            {
                if (!_sources.TryGetValue(operatorSourceId!, out var previous))
                {
                    if (_sources.Count >= MaxSources)
                        return Assess(RedisAuditSinkHealthStatus.TrackingCapacityExceeded,
                            "R437_AUDIT_METRICS_TRACKER_FULL");
                    _sources.Add(operatorSourceId!, (sample, false));
                    return Assess(RedisAuditSinkHealthStatus.BaselineOnly,
                        "R437_AUDIT_METRICS_BASELINE_ONLY");
                }

                if (previous.Compromised)
                    return Assess(RedisAuditSinkHealthStatus.PreviouslyCompromised,
                        "R437_AUDIT_METRICS_PREVIOUSLY_COMPROMISED");

                var before = previous.Value;
                if (sample.ScrapedAtUtc <= before.ScrapedAtUtc
                    || sample.SentMessages < before.SentMessages
                    || sample.DroppedMessages < before.DroppedMessages
                    || sample.DisconnectLossEvents < before.DisconnectLossEvents
                    || sample.ReconnectAttemptsExhausted
                        < before.ReconnectAttemptsExhausted)
                {
                    _sources[operatorSourceId!] = (before, true);
                    return Assess(RedisAuditSinkHealthStatus.CounterResetOrStaleOrder,
                        "R437_AUDIT_METRICS_COUNTER_RESET_OR_REORDER");
                }

                _sources[operatorSourceId!] = (sample, false);
                if (sample.DroppedMessages > before.DroppedMessages
                    || sample.DisconnectLossEvents > before.DisconnectLossEvents
                    || sample.ReconnectAttemptsExhausted
                        > before.ReconnectAttemptsExhausted)
                {
                    _sources[operatorSourceId!] = (sample, true);
                    return Assess(RedisAuditSinkHealthStatus.LossCounterIncrease,
                        "R437_AUDIT_METRICS_DELIVERY_LOSS");
                }

                if (sample.PendingBytes > 0)
                    return Assess(RedisAuditSinkHealthStatus.PendingBacklog,
                        "R437_AUDIT_METRICS_PENDING_BACKLOG");

                return Assess(RedisAuditSinkHealthStatus.NoObservedLossDelta,
                    "R437_AUDIT_METRICS_NO_OBSERVED_DROP_DELTA");
            }
        }

        private static RedisAuditSinkHealthAssessment Assess(
            RedisAuditSinkHealthStatus status, string diagnostic)
            => new(status, diagnostic);

        private static bool ValidSourceId(string? id)
        {
            if (id is not { Length: >= 3 and <= 64 }) return false;
            foreach (var c in id)
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
                    return false;
            return true;
        }
    }
}
