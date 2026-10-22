// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleRuntimeStats.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public sealed record RuleRuntimeStats(
        string RuleId,
        long Evaluations,
        long Matches,
        long NoMatches,
        long Suppressed,
        long Failed,
        long Skipped,
        long MissingTelemetryCount,
        long CooldownHitCount,
        double AverageDurationMicroseconds,
        double MaxDurationMicroseconds,
        DateTime? LastEvaluatedUtc,
        DateTime? LastMatchedUtc,
        DateTime? LastFailedUtc)
    {
        public double MatchRate => Evaluations <= 0 ? 0.0 : (double)Matches / Evaluations;
        public double FailureRate => Evaluations <= 0 ? 0.0 : (double)Failed / Evaluations;
        public double MissingTelemetryRate => Evaluations + Skipped <= 0 ? 0.0 : (double)MissingTelemetryCount / (Evaluations + Skipped);
    }

    internal sealed class RuleRuntimeStatsState
    {
        public long Evaluations;
        public long Matches;
        public long NoMatches;
        public long Suppressed;
        public long Failed;
        public long Skipped;
        public long MissingTelemetryCount;
        public long CooldownHitCount;
        public long DurationTicks;
        public long DurationCount;
        public long MaxDurationTicks;
        public DateTime? LastEvaluatedUtc;
        public DateTime? LastMatchedUtc;
        public DateTime? LastFailedUtc;
    }

    public static class RuleRuntimeStatsStore
    {
        private static readonly ConcurrentDictionary<string, RuleRuntimeStatsState> _states = new(StringComparer.OrdinalIgnoreCase);

        public static void RecordResult(string ruleId, RuleEvaluationResult result, DateTime timestampUtc, TimeSpan? duration = null, bool missingTelemetry = false, bool cooldownHit = false)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            var id = string.IsNullOrWhiteSpace(ruleId) ? result.RuleId : ruleId;
            if (string.IsNullOrWhiteSpace(id)) return;

            var state = GetState(id);
            lock (state)
            {
                if (result.Skipped)
                    state.Skipped++;

                if (result.Evaluated)
                {
                    state.Evaluations++;
                    state.LastEvaluatedUtc = timestampUtc;
                }

                if (result.Matched)
                {
                    state.Matches++;
                    state.LastMatchedUtc = timestampUtc;
                }
                else if (result.Evaluated && !result.Failed)
                {
                    state.NoMatches++;
                }

                if (result.Suppressed)
                    state.Suppressed++;

                if (result.Failed)
                {
                    state.Failed++;
                    state.LastFailedUtc = timestampUtc;
                }

                if (missingTelemetry)
                    state.MissingTelemetryCount++;
                if (cooldownHit)
                    state.CooldownHitCount++;

                if (duration.HasValue)
                    RecordDurationLocked(state, duration.Value);
            }
        }

        public static void RecordSelectorSkipped(string ruleId, DateTime timestampUtc, bool missingTelemetry)
        {
            if (string.IsNullOrWhiteSpace(ruleId)) return;
            var state = GetState(ruleId);
            lock (state)
            {
                state.Skipped++;
                if (missingTelemetry)
                    state.MissingTelemetryCount++;
            }
        }

        public static void RecordDuration(string ruleId, TimeSpan duration)
        {
            if (string.IsNullOrWhiteSpace(ruleId)) return;
            var state = GetState(ruleId);
            lock (state)
            {
                RecordDurationLocked(state, duration);
            }
        }

        public static RuleRuntimeStats Snapshot(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                throw new ArgumentException("Rule ID is required.", nameof(ruleId));

            if (!_states.TryGetValue(ruleId, out var state))
                return Empty(ruleId);

            lock (state)
            {
                return Build(ruleId, state);
            }
        }

        public static IReadOnlyList<RuleRuntimeStats> SnapshotAll()
            => _states.Keys.OrderBy(static key => key, StringComparer.OrdinalIgnoreCase).Select(Snapshot).ToArray();

        public static void Reset() => _states.Clear();

        private static RuleRuntimeStatsState GetState(string ruleId)
            => _states.GetOrAdd(ruleId.Trim(), static _ => new RuleRuntimeStatsState());

        private static void RecordDurationLocked(RuleRuntimeStatsState state, TimeSpan duration)
        {
            var ticks = Math.Max(0, duration.Ticks);
            state.DurationTicks += ticks;
            state.DurationCount++;
            if (ticks > state.MaxDurationTicks)
                state.MaxDurationTicks = ticks;
        }

        private static RuleRuntimeStats Empty(string ruleId)
            => new(ruleId, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, null, null, null);

        private static RuleRuntimeStats Build(string ruleId, RuleRuntimeStatsState state)
        {
            var averageTicks = state.DurationCount <= 0 ? 0.0 : (double)state.DurationTicks / state.DurationCount;
            return new RuleRuntimeStats(
                ruleId,
                Interlocked.Read(ref state.Evaluations),
                Interlocked.Read(ref state.Matches),
                Interlocked.Read(ref state.NoMatches),
                Interlocked.Read(ref state.Suppressed),
                Interlocked.Read(ref state.Failed),
                Interlocked.Read(ref state.Skipped),
                Interlocked.Read(ref state.MissingTelemetryCount),
                Interlocked.Read(ref state.CooldownHitCount),
                TimeSpan.FromTicks((long)averageTicks).TotalMicroseconds,
                TimeSpan.FromTicks(state.MaxDurationTicks).TotalMicroseconds,
                state.LastEvaluatedUtc,
                state.LastMatchedUtc,
                state.LastFailedUtc);
        }
    }
}
