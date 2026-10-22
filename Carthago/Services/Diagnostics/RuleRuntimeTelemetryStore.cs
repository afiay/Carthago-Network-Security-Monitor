// SPDX-License-Identifier: MIT
// File: Services/Diagnostics/RuleRuntimeTelemetryStore.cs
using System;
using System.Collections.Concurrent;

namespace Carthago.Services.Diagnostics
{
    public sealed record RuleRuntimeTelemetrySnapshot(
        string RuleId,
        DateTime? LastSelectedUtc,
        DateTime? LastSkippedUtc,
        DateTime? LastEvaluatedUtc,
        DateTime? LastMatchedUtc,
        DateTime? LastPersistedUtc,
        DateTime? LastFailureUtc,
        string? LastFailure,
        DateTime? LastTuningDecisionUtc,
        string? LastTuningDecisionSummary,
        long SelectorSelectedCount,
        long SelectorSkippedCount,
        long MissingTelemetryCount,
        long EvaluatedCount,
        long MatchedCount,
        long PersistedCount,
        double ConfidenceSum,
        long ConfidenceCount)
    {
        public double AverageConfidence => ConfidenceCount <= 0 ? 0.0 : ConfidenceSum / ConfidenceCount;
        public double MissingTelemetryRate
            => SelectorSelectedCount + SelectorSkippedCount <= 0
                ? 0.0
                : (double)MissingTelemetryCount / (SelectorSelectedCount + SelectorSkippedCount);
    }

    internal sealed class RuleRuntimeTelemetryState
    {
        public DateTime? LastSelectedUtc { get; set; }
        public DateTime? LastSkippedUtc { get; set; }
        public DateTime? LastEvaluatedUtc { get; set; }
        public DateTime? LastMatchedUtc { get; set; }
        public DateTime? LastPersistedUtc { get; set; }
        public DateTime? LastFailureUtc { get; set; }
        public string? LastFailure { get; set; }
        public DateTime? LastTuningDecisionUtc { get; set; }
        public string? LastTuningDecisionSummary { get; set; }
        public long SelectorSelectedCount { get; set; }
        public long SelectorSkippedCount { get; set; }
        public long MissingTelemetryCount { get; set; }
        public long EvaluatedCount { get; set; }
        public long MatchedCount { get; set; }
        public long PersistedCount { get; set; }
        public double ConfidenceSum { get; set; }
        public long ConfidenceCount { get; set; }
    }

    public static class RuleRuntimeTelemetryStore
    {
        private static readonly ConcurrentDictionary<string, RuleRuntimeTelemetryState> _states = new(StringComparer.OrdinalIgnoreCase);

        public static void RecordSelectorSelected(string ruleId, DateTime timestampUtc)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.SelectorSelectedCount++;
                state.LastSelectedUtc = timestampUtc;
            }
        }

        public static void RecordSelectorSkipped(string ruleId, DateTime timestampUtc, bool missingTelemetry)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.SelectorSkippedCount++;
                state.LastSkippedUtc = timestampUtc;
                if (missingTelemetry)
                    state.MissingTelemetryCount++;
            }
        }

        public static void RecordEvaluated(string ruleId, DateTime timestampUtc)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.EvaluatedCount++;
                state.LastEvaluatedUtc = timestampUtc;
            }
        }

        public static void RecordMatched(string ruleId, DateTime timestampUtc, double confidenceScore)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.MatchedCount++;
                state.LastMatchedUtc = timestampUtc;
                if (confidenceScore > 0)
                {
                    state.ConfidenceSum += confidenceScore;
                    state.ConfidenceCount++;
                }
            }
        }

        public static void RecordPersisted(string ruleId, DateTime timestampUtc, double confidenceScore)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.PersistedCount++;
                state.LastPersistedUtc = timestampUtc;
                if (confidenceScore > 0)
                {
                    state.ConfidenceSum += confidenceScore;
                    state.ConfidenceCount++;
                }
            }
        }

        public static void RecordFailure(string ruleId, DateTime timestampUtc, string? failure)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.LastFailureUtc = timestampUtc;
                state.LastFailure = string.IsNullOrWhiteSpace(failure) ? null : failure.Trim();
            }
        }

        public static void RecordTuningDecision(string ruleId, DateTime timestampUtc, string? summary)
        {
            var state = GetState(ruleId);
            lock (state)
            {
                state.LastTuningDecisionUtc = timestampUtc;
                state.LastTuningDecisionSummary = string.IsNullOrWhiteSpace(summary) ? null : summary.Trim();
            }
        }

        public static RuleRuntimeTelemetrySnapshot Snapshot(string ruleId)
        {
            if (!_states.TryGetValue(ruleId, out var state))
            {
                return new RuleRuntimeTelemetrySnapshot(
                    ruleId,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0.0,
                    0);
            }

            lock (state)
            {
                return new RuleRuntimeTelemetrySnapshot(
                    ruleId,
                    state.LastSelectedUtc,
                    state.LastSkippedUtc,
                    state.LastEvaluatedUtc,
                    state.LastMatchedUtc,
                    state.LastPersistedUtc,
                    state.LastFailureUtc,
                    state.LastFailure,
                    state.LastTuningDecisionUtc,
                    state.LastTuningDecisionSummary,
                    state.SelectorSelectedCount,
                    state.SelectorSkippedCount,
                    state.MissingTelemetryCount,
                    state.EvaluatedCount,
                    state.MatchedCount,
                    state.PersistedCount,
                    state.ConfidenceSum,
                    state.ConfidenceCount);
            }
        }

        public static void Reset() => _states.Clear();

        private static RuleRuntimeTelemetryState GetState(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                throw new ArgumentException("Rule ID is required.", nameof(ruleId));

            return _states.GetOrAdd(ruleId.Trim(), _ => new RuleRuntimeTelemetryState());
        }
    }
}
