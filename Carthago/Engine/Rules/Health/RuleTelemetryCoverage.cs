// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleTelemetryCoverage.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Engine.Rules.Health
{
    public enum RuleTelemetryCoverageState
    {
        Unknown,
        Unsupported,
        Partial,
        Full
    }

    public sealed record TelemetryKindObservation(
        RuleTelemetryKind Kind,
        long Count,
        DateTime? LastObservedUtc);

    public sealed record RuleTelemetryCoverageImpact(
        string RuleId,
        RuleTelemetryCoverageState State,
        IReadOnlyList<RuleTelemetryKind> RequiredTelemetry,
        IReadOnlyList<RuleTelemetryKind> ObservedRequiredTelemetry,
        IReadOnlyList<RuleTelemetryKind> MissingRequiredTelemetry,
        IReadOnlyList<string> MissingRequiredFields,
        DateTime? LastAnyRequiredTelemetryUtc)
    {
        public double CoverageRatio => RequiredTelemetry.Count == 0
            ? 1.0
            : (double)ObservedRequiredTelemetry.Count / RequiredTelemetry.Count;
    }

    public sealed record TelemetryCoverageSnapshot(
        DateTime CreatedUtc,
        long RecordsObserved,
        IReadOnlyList<TelemetryKindObservation> ObservedTelemetry,
        IReadOnlyList<RuleTelemetryCoverageImpact> RuleImpacts)
    {
        public IReadOnlyList<RuleTelemetryKind> AvailableKinds => ObservedTelemetry
            .Where(static observation => observation.Count > 0)
            .Select(static observation => observation.Kind)
            .Distinct()
            .OrderBy(static kind => kind.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    internal sealed class TelemetryKindObservationState
    {
        public long Count;
        public DateTime? LastObservedUtc;
    }

    public static class RuleTelemetryCoverageStore
    {
        private static readonly ConcurrentDictionary<RuleTelemetryKind, TelemetryKindObservationState> _observations = new();
        private static long _recordsObserved;

        public static void ObserveRecord(TrafficRecord? record, DateTime timestampUtc)
        {
            if (record == null)
                return;

            System.Threading.Interlocked.Increment(ref _recordsObserved);
            foreach (RuleTelemetryKind kind in Enum.GetValues(typeof(RuleTelemetryKind)))
            {
                if (!RulePrecisionCatalog.HasTelemetryKind(kind, record))
                    continue;

                var state = _observations.GetOrAdd(kind, static _ => new TelemetryKindObservationState());
                lock (state)
                {
                    state.Count++;
                    state.LastObservedUtc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
                }
            }
        }

        public static IReadOnlyList<TelemetryKindObservation> SnapshotObservations()
        {
            return Enum.GetValues(typeof(RuleTelemetryKind))
                .Cast<RuleTelemetryKind>()
                .Select(kind =>
                {
                    if (!_observations.TryGetValue(kind, out var state))
                        return new TelemetryKindObservation(kind, 0, null);

                    lock (state)
                    {
                        return new TelemetryKindObservation(kind, state.Count, state.LastObservedUtc);
                    }
                })
                .OrderBy(static observation => observation.Kind.ToString(), StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public static bool HasObserved(RuleTelemetryKind kind)
            => _observations.TryGetValue(kind, out var state) && System.Threading.Interlocked.Read(ref state.Count) > 0;

        public static DateTime? LastObservedUtc(RuleTelemetryKind kind)
        {
            if (!_observations.TryGetValue(kind, out var state))
                return null;

            lock (state)
            {
                return state.LastObservedUtc;
            }
        }

        public static long RecordsObserved => System.Threading.Interlocked.Read(ref _recordsObserved);

        public static void Reset()
        {
            _observations.Clear();
            System.Threading.Interlocked.Exchange(ref _recordsObserved, 0);
        }
    }

    public sealed class RuleTelemetryCoverageService
    {
        private readonly Func<IReadOnlyList<IDetectionRule>> _ruleProvider;

        public RuleTelemetryCoverageService(Func<IReadOnlyList<IDetectionRule>>? ruleProvider = null)
            => _ruleProvider = ruleProvider ?? (() => RuleRegistry.CreateDefaultRules());

        public TelemetryCoverageSnapshot Snapshot()
        {
            var rules = _ruleProvider().OrderBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase).ToArray();
            var observations = RuleTelemetryCoverageStore.SnapshotObservations();
            var impacts = rules.Select(rule => BuildImpact(rule.Descriptor.RuleId, rule.Intelligence?.PrecisionProfile ?? RulePrecisionCatalog.GetProfile(rule.Descriptor))).ToArray();
            return new TelemetryCoverageSnapshot(DateTime.UtcNow, RuleTelemetryCoverageStore.RecordsObserved, observations, impacts);
        }

        public RuleTelemetryCoverageImpact GetImpact(IDetectionRule rule)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));
            return BuildImpact(rule.Descriptor.RuleId, rule.Intelligence?.PrecisionProfile ?? RulePrecisionCatalog.GetProfile(rule.Descriptor));
        }

        private static RuleTelemetryCoverageImpact BuildImpact(string ruleId, RulePrecisionProfile profile)
        {
            var required = profile.RequiredTelemetry.OrderBy(static kind => kind.ToString(), StringComparer.OrdinalIgnoreCase).ToArray();
            var observed = required.Where(RuleTelemetryCoverageStore.HasObserved).ToArray();
            var missing = required.Except(observed).ToArray();
            var missingFields = Array.Empty<string>();
            var lastObserved = observed
                .Select(RuleTelemetryCoverageStore.LastObservedUtc)
                .Where(static value => value.HasValue)
                .Select(static value => value!.Value)
                .DefaultIfEmpty()
                .Max();

            var state = required.Length == 0
                ? RuleTelemetryCoverageState.Full
                : observed.Length == 0
                    ? RuleTelemetryCoverageState.Unsupported
                    : observed.Length == required.Length
                        ? RuleTelemetryCoverageState.Full
                        : RuleTelemetryCoverageState.Partial;

            return new RuleTelemetryCoverageImpact(ruleId, state, required, observed, missing, missingFields, lastObserved == default ? null : lastObserved);
        }
    }
}
