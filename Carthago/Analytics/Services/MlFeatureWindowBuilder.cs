// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class MlFeatureWindowBuilder
    {
        private readonly TimeSpan _window;
        private readonly int _maxHosts;
        private readonly int _maxKnownValues;
        private readonly Dictionary<string, HostWindowState> _hosts = new(StringComparer.OrdinalIgnoreCase);

        public MlFeatureWindowBuilder(TimeSpan? window = null, int maxHosts = 1024, int maxKnownValues = 512)
        {
            _window = window ?? TimeSpan.FromMinutes(5);
            _maxHosts = Math.Max(32, maxHosts);
            _maxKnownValues = Math.Max(32, maxKnownValues);
        }

        public IReadOnlyList<MlFeatureWindow> ObserveTraffic(FlowFeature feature)
        {
            if (feature == null || string.IsNullOrWhiteSpace(feature.SourceIp))
                return Array.Empty<MlFeatureWindow>();

            var state = GetOrCreateState(feature.SourceIp, NormalizeTimestamp(feature.TimestampUtc));
            var completed = RotateIfNeeded(state, NormalizeTimestamp(feature.TimestampUtc));
            ObserveFeature(state, feature, countRuleHit: false);
            return completed;
        }

        public IReadOnlyList<MlFeatureWindow> ObserveDetection(DetectionEvent evt, FlowFeature feature)
        {
            if (evt == null || feature == null || string.IsNullOrWhiteSpace(feature.SourceIp))
                return Array.Empty<MlFeatureWindow>();

            var timestampUtc = NormalizeTimestamp(feature.TimestampUtc);
            var state = GetOrCreateState(feature.SourceIp, timestampUtc);
            var completed = RotateIfNeeded(state, timestampUtc);
            ObserveFeature(state, feature, countRuleHit: true);

            if (evt.Severity >= SeverityLevel.High)
                state.CurrentThreatIntelHitCount += evt.RuleId is "R003" or "R016" ? 1 : 0;

            return completed;
        }

        public IReadOnlyList<MlFeatureWindow> ObserveAnomaly(AnomalySignal anomaly)
        {
            if (anomaly == null || string.IsNullOrWhiteSpace(anomaly.SourceIp))
                return Array.Empty<MlFeatureWindow>();

            var timestampUtc = NormalizeTimestamp(anomaly.UpdatedUtc == default ? anomaly.CreatedUtc : anomaly.UpdatedUtc);
            var state = GetOrCreateState(anomaly.SourceIp, timestampUtc);
            var completed = RotateIfNeeded(state, timestampUtc);

            switch (anomaly.Category)
            {
                case "DestinationNovelty":
                    state.CurrentNewDestinationCount++;
                    break;
                case "GeoAnomaly":
                    state.CurrentNewCountryCount++;
                    state.CurrentNewAsnCount++;
                    break;
                case "FingerprintNovelty":
                    state.CurrentRareFingerprintCount++;
                    break;
                case "ThreatIntelMatch":
                case "ReputationHit":
                    state.CurrentThreatIntelHitCount++;
                    break;
            }

            return completed;
        }

        public IReadOnlyList<MlFeatureWindow> Flush(DateTime uptoUtc)
        {
            var completed = new List<MlFeatureWindow>();
            foreach (var state in _hosts.Values.ToArray())
                completed.AddRange(RotateIfNeeded(state, NormalizeTimestamp(uptoUtc), forceCloseBeforeTimestamp: true));
            return completed;
        }

        private HostWindowState GetOrCreateState(string sourceIp, DateTime timestampUtc)
        {
            if (_hosts.TryGetValue(sourceIp, out var existing))
                return existing;

            if (_hosts.Count >= _maxHosts)
            {
                var oldest = _hosts.Values.OrderBy(v => v.LastSeenUtc).FirstOrDefault();
                if (oldest != null)
                    _hosts.Remove(oldest.SourceIp);
            }

            var state = new HostWindowState(sourceIp, _window)
            {
                CurrentWindowStartUtc = AlignWindow(timestampUtc),
                LastSeenUtc = timestampUtc
            };
            _hosts[sourceIp] = state;
            return state;
        }

        private IReadOnlyList<MlFeatureWindow> RotateIfNeeded(HostWindowState state, DateTime timestampUtc, bool forceCloseBeforeTimestamp = false)
        {
            var completed = new List<MlFeatureWindow>();

            if (state.CurrentWindowStartUtc == default)
            {
                state.CurrentWindowStartUtc = AlignWindow(timestampUtc);
                state.LastSeenUtc = timestampUtc;
                return completed;
            }

            var nextWindowStartUtc = AlignWindow(timestampUtc);
            while (state.CurrentWindowStartUtc != default
                   && (forceCloseBeforeTimestamp
                       ? state.CurrentWindowStartUtc + _window <= nextWindowStartUtc
                       : state.CurrentWindowStartUtc + _window <= timestampUtc))
            {
                completed.Add(BuildWindow(state));
                state.ResetWindow(state.CurrentWindowStartUtc + _window);
            }

            state.LastSeenUtc = timestampUtc;
            return completed;
        }

        private void ObserveFeature(HostWindowState state, FlowFeature feature, bool countRuleHit)
        {
            state.LastSeenUtc = NormalizeTimestamp(feature.TimestampUtc);

            if (string.Equals(feature.Direction, "outbound", StringComparison.OrdinalIgnoreCase))
                state.CurrentOutboundBytes += Math.Max(0, feature.Bytes);

            AddBounded(state.CurrentUniqueDestinations, feature.DestinationIp, 2048);
            if (feature.DestinationPort.HasValue)
                AddBounded(state.CurrentUniquePorts, feature.DestinationPort.Value.ToString(CultureInfo.InvariantCulture), 512);

            var newDestinationCount = state.CurrentNewDestinationCount;
            var newAsnCount = state.CurrentNewAsnCount;
            var newCountryCount = state.CurrentNewCountryCount;

            ObserveNovelty(state.KnownDestinations, feature.DestinationIp, ref newDestinationCount, _maxKnownValues);
            ObserveNovelty(state.KnownAsns, feature.Asn, ref newAsnCount, _maxKnownValues);
            ObserveNovelty(state.KnownCountries, feature.Country, ref newCountryCount, _maxKnownValues);

            state.CurrentNewDestinationCount = newDestinationCount;
            state.CurrentNewAsnCount = newAsnCount;
            state.CurrentNewCountryCount = newCountryCount;

            var fingerprint = !string.IsNullOrWhiteSpace(feature.Ja4) ? feature.Ja4 : feature.Hassh;
            float ignoredCount = 0;
            if (ObserveNovelty(state.KnownFingerprints, fingerprint, ref ignoredCount, _maxKnownValues))
            {
                if (state.ClosedWindowCount >= 3)
                    state.CurrentRareFingerprintCount++;
            }

            if (feature.IsThreatFeedHit)
                state.CurrentThreatIntelHitCount++;

            if (countRuleHit)
            {
                state.CurrentRuleHitCount += Math.Max(1, feature.PacketCount);
                state.CurrentSeverityWeightedRuleCount += SeverityWeight(feature.DetectionSeverity);
                if (feature.RuleId is "R003" or "R016")
                    state.CurrentThreatIntelHitCount++;
            }
        }

        private MlFeatureWindow BuildWindow(HostWindowState state)
        {
            var startUtc = state.CurrentWindowStartUtc;
            var endUtc = startUtc + _window;
            return new MlFeatureWindow
            {
                WindowStartUtc = startUtc,
                WindowEndUtc = endUtc,
                SourceIp = state.SourceIp,
                OutboundBytes = ClampFloat(state.CurrentOutboundBytes),
                UniqueDestinationCount = state.CurrentUniqueDestinations.Count,
                UniquePortCount = state.CurrentUniquePorts.Count,
                RuleHitCount = ClampFloat(state.CurrentRuleHitCount),
                SeverityWeightedRuleCount = ClampFloat(state.CurrentSeverityWeightedRuleCount),
                NewDestinationCount = state.CurrentNewDestinationCount,
                NewAsnCount = state.CurrentNewAsnCount,
                NewCountryCount = state.CurrentNewCountryCount,
                RareFingerprintCount = state.CurrentRareFingerprintCount,
                ThreatIntelHitCount = state.CurrentThreatIntelHitCount,
                HourOfDay = startUtc.Hour,
                DayOfWeek = (float)startUtc.DayOfWeek
            };
        }

        private DateTime AlignWindow(DateTime timestampUtc)
        {
            var minutes = Math.Max(1, (int)Math.Round(_window.TotalMinutes));
            return new DateTime(
                timestampUtc.Year,
                timestampUtc.Month,
                timestampUtc.Day,
                timestampUtc.Hour,
                (timestampUtc.Minute / minutes) * minutes,
                0,
                DateTimeKind.Utc);
        }

        private static DateTime NormalizeTimestamp(DateTime timestampUtc)
        {
            if (timestampUtc == default)
                return DateTime.UtcNow;

            return timestampUtc.Kind switch
            {
                DateTimeKind.Utc => timestampUtc,
                DateTimeKind.Local => timestampUtc.ToUniversalTime(),
                _ => DateTime.SpecifyKind(timestampUtc, DateTimeKind.Utc)
            };
        }

        private static void AddBounded(HashSet<string> set, string? value, int maxEntries)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;

            var normalized = value.Trim();
            if (set.Count >= maxEntries && !set.Contains(normalized))
                return;

            set.Add(normalized);
        }

        private static bool ObserveNovelty(HashSet<string> knownSet, string? value, ref float count, int maxKnownValues)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var normalized = value.Trim();
            if (knownSet.Contains(normalized))
                return false;

            if (knownSet.Count < Math.Max(32, maxKnownValues))
                knownSet.Add(normalized);

            count++;
            return true;
        }

        private static float ClampFloat(double value)
        {
            if (!double.IsFinite(value))
                return 0;

            return (float)Math.Clamp(value, 0, float.MaxValue);
        }

        private static float SeverityWeight(SeverityLevel? severity)
        {
            return severity switch
            {
                SeverityLevel.Critical => 4f,
                SeverityLevel.High => 3f,
                SeverityLevel.Medium => 2f,
                SeverityLevel.Low => 1f,
                _ => 0f
            };
        }

        private sealed class HostWindowState
        {
            public HostWindowState(string sourceIp, TimeSpan window)
            {
                SourceIp = sourceIp;
                Window = window;
            }

            public string SourceIp { get; }
            public TimeSpan Window { get; }
            public DateTime CurrentWindowStartUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public int ClosedWindowCount { get; set; }

            public HashSet<string> KnownDestinations { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownAsns { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownCountries { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownFingerprints { get; } = new(StringComparer.OrdinalIgnoreCase);

            public double CurrentOutboundBytes { get; set; }
            public HashSet<string> CurrentUniqueDestinations { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentUniquePorts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public float CurrentRuleHitCount { get; set; }
            public float CurrentSeverityWeightedRuleCount { get; set; }
            public float CurrentNewDestinationCount { get; set; }
            public float CurrentNewAsnCount { get; set; }
            public float CurrentNewCountryCount { get; set; }
            public float CurrentRareFingerprintCount { get; set; }
            public float CurrentThreatIntelHitCount { get; set; }

            public void ResetWindow(DateTime nextWindowStartUtc)
            {
                ClosedWindowCount++;
                CurrentWindowStartUtc = nextWindowStartUtc;
                CurrentOutboundBytes = 0;
                CurrentUniqueDestinations.Clear();
                CurrentUniquePorts.Clear();
                CurrentRuleHitCount = 0;
                CurrentSeverityWeightedRuleCount = 0;
                CurrentNewDestinationCount = 0;
                CurrentNewAsnCount = 0;
                CurrentNewCountryCount = 0;
                CurrentRareFingerprintCount = 0;
                CurrentThreatIntelHitCount = 0;
            }
        }
    }
}
