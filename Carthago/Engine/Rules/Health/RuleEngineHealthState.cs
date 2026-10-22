// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleEngineHealthState.cs
using System;
using System.Threading;

namespace Carthago.Services
{
    public sealed record RuleEngineHealthSnapshot(
        DateTime TimestampUtc,
        DateTime? LastEvaluationUtc,
        long EvaluationCount,
        long CaptureDropDelta,
        long SinkBackpressureCount,
        long JournalWriteFailureCount,
        long ConfigReloadFailureCount,
        DateTime? LastThreatFeedUpdateUtc,
        TimeSpan ClockSkew)
    {
        public static RuleEngineHealthSnapshot Empty(DateTime nowUtc) => new(nowUtc, null, 0, 0, 0, 0, 0, null, TimeSpan.Zero);
    }

    public static class RuleEngineHealthState
    {
        private static long _evaluationCount;
        private static long _captureDropCount;
        private static long _lastCaptureDropSnapshot;
        private static long _sinkBackpressureCount;
        private static long _journalWriteFailureCount;
        private static long _configReloadFailureCount;
        private static DateTime? _lastEvaluationUtc;
        private static DateTime? _lastThreatFeedUpdateUtc;
        private static DateTime _lastWallClockUtc = DateTime.UtcNow;
        private static DateTime _lastMonotonicBaseUtc = DateTime.UtcNow;

        public static void RecordEvaluationStart(DateTime timestampUtc)
        {
            Interlocked.Increment(ref _evaluationCount);
            _lastEvaluationUtc = timestampUtc;
            var now = DateTime.UtcNow;
            _lastMonotonicBaseUtc = now;
            _lastWallClockUtc = now;
        }

        public static void ReportCaptureDrops(long count) => Interlocked.Add(ref _captureDropCount, Math.Max(0, count));
        public static void ReportSinkQueueBackpressure(string? reason = null) => Interlocked.Increment(ref _sinkBackpressureCount);
        public static void ReportJournalWriteFailure(string? path, string? reason) => Interlocked.Increment(ref _journalWriteFailureCount);
        public static void ReportConfigReloadFailure(string? reason) => Interlocked.Increment(ref _configReloadFailureCount);
        public static void ReportThreatFeedUpdated(DateTime timestampUtc) => _lastThreatFeedUpdateUtc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
        public static void ReportClockSkew(DateTime observedWallClockUtc, DateTime referenceUtc)
        {
            _lastWallClockUtc = observedWallClockUtc.Kind == DateTimeKind.Utc ? observedWallClockUtc : observedWallClockUtc.ToUniversalTime();
            _lastMonotonicBaseUtc = referenceUtc.Kind == DateTimeKind.Utc ? referenceUtc : referenceUtc.ToUniversalTime();
        }

        public static RuleEngineHealthSnapshot Snapshot(DateTime timestampUtc)
        {
            var totalDrops = Interlocked.Read(ref _captureDropCount);
            var previousDrops = Interlocked.Exchange(ref _lastCaptureDropSnapshot, totalDrops);
            var now = DateTime.UtcNow;
            var clockSkew = now - _lastWallClockUtc;
            return new RuleEngineHealthSnapshot(
                timestampUtc,
                _lastEvaluationUtc,
                Interlocked.Read(ref _evaluationCount),
                Math.Max(0, totalDrops - previousDrops),
                Interlocked.Read(ref _sinkBackpressureCount),
                Interlocked.Read(ref _journalWriteFailureCount),
                Interlocked.Read(ref _configReloadFailureCount),
                _lastThreatFeedUpdateUtc,
                clockSkew);
        }

        public static void Reset()
        {
            Interlocked.Exchange(ref _evaluationCount, 0);
            Interlocked.Exchange(ref _captureDropCount, 0);
            Interlocked.Exchange(ref _lastCaptureDropSnapshot, 0);
            Interlocked.Exchange(ref _sinkBackpressureCount, 0);
            Interlocked.Exchange(ref _journalWriteFailureCount, 0);
            Interlocked.Exchange(ref _configReloadFailureCount, 0);
            _lastEvaluationUtc = null;
            _lastThreatFeedUpdateUtc = null;
            _lastWallClockUtc = DateTime.UtcNow;
            _lastMonotonicBaseUtc = DateTime.UtcNow;
        }
    }
}
