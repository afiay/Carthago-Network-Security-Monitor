// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class BaselineEngine
    {
        private readonly TimeSpan _window;
        private readonly int _maxHosts;
        private readonly int _maxKnownValues;
        private readonly Dictionary<string, HostState> _hosts = new(StringComparer.OrdinalIgnoreCase);
        private DateTime? _lastUpdatedUtc;

        public BaselineEngine(
            TimeSpan? learningWindow = null,
            IEnumerable<BaselineSnapshot>? snapshots = null,
            int maxHosts = 1024,
            int maxKnownValues = 512)
        {
            _window = learningWindow ?? TimeSpan.FromMinutes(5);
            _maxHosts = Math.Max(32, maxHosts);
            _maxKnownValues = Math.Max(32, maxKnownValues);

            if (snapshots == null)
                return;

            foreach (var snapshot in snapshots)
            {
                if (snapshot == null || string.IsNullOrWhiteSpace(snapshot.HostId))
                    continue;

                _hosts[snapshot.HostId] = HostState.FromSnapshot(snapshot, _window);
                _lastUpdatedUtc = snapshot.LastUpdatedUtc > (_lastUpdatedUtc ?? DateTime.MinValue)
                    ? snapshot.LastUpdatedUtc
                    : _lastUpdatedUtc;
            }
        }

        public IReadOnlyList<AnomalySignal> ObserveTraffic(FlowFeature feature)
        {
            if (feature == null) throw new ArgumentNullException(nameof(feature));
            if (string.IsNullOrWhiteSpace(feature.SourceIp))
                return Array.Empty<AnomalySignal>();

            feature.TimestampUtc = NormalizeTimestamp(feature.TimestampUtc);
            var anomalies = new List<AnomalySignal>();
            var state = GetHostState(feature.SourceIp);

            RotateWindowIfNeeded(state, feature.TimestampUtc, anomalies);
            state.LastSeenUtc = feature.TimestampUtc;
            _lastUpdatedUtc = feature.TimestampUtc;

            state.CurrentWindowOutboundBytes += Math.Max(0, feature.Bytes);
            AddBounded(state.CurrentWindowUniqueDestinations, feature.DestinationIp, 2048);
            if (feature.DestinationPort.HasValue)
                AddBounded(state.CurrentWindowUniquePorts, feature.DestinationPort.Value.ToString(CultureInfo.InvariantCulture), 512);
            if (feature.IsDns)
                state.CurrentWindowDnsQueries++;

            ObserveNovelty(state.KnownDestinations, feature.DestinationIp, state.CurrentWindowNewDestinations, _maxKnownValues, out var newDestination);
            ObserveNovelty(state.KnownCountries, feature.Country, state.CurrentWindowNewCountries, _maxKnownValues, out var newCountry);
            ObserveNovelty(state.KnownAsns, feature.Asn, state.CurrentWindowNewAsns, _maxKnownValues, out var newAsn);
            ObserveNovelty(state.KnownPorts, feature.DestinationPort?.ToString(CultureInfo.InvariantCulture), state.CurrentWindowNewPorts, _maxKnownValues, out var newPort);
            ObserveNovelty(state.KnownJa4Fingerprints, feature.Ja4, state.CurrentWindowNewJa4, _maxKnownValues, out var newJa4);
            ObserveNovelty(state.KnownHasshFingerprints, feature.Hassh, state.CurrentWindowNewHassh, _maxKnownValues, out var newHassh);
            ObserveNovelty(state.KnownProcesses, feature.ProcessName, state.CurrentWindowNewProcesses, _maxKnownValues, out var newProcess);

            if (state.Confidence != "Low" && newDestination && !feature.IsInternalDestination)
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "DestinationNovelty",
                    $"New external destination contacted by {feature.SourceIp}",
                    $"{feature.SourceIp} contacted destination {feature.DestinationIp} that has not previously been observed for this host.",
                    0.52,
                    "medium",
                    $"Destination {feature.DestinationIp} not previously seen for {feature.SourceIp}",
                    feature.DestinationIp ?? "",
                    feature.Country ?? "",
                    feature.Asn ?? ""));
            }

            if (state.Confidence != "Low" && newCountry && !string.IsNullOrWhiteSpace(feature.Country))
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "GeoAnomaly",
                    $"New country observed for {feature.SourceIp}",
                    $"{feature.SourceIp} contacted country {feature.Country} that is new for this host baseline.",
                    0.48,
                    "medium",
                    $"Country {feature.Country} not previously seen for {feature.SourceIp}"));
            }

            if (state.Confidence != "Low" && newAsn && !string.IsNullOrWhiteSpace(feature.Asn))
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "BehaviorChange",
                    $"New ASN observed for {feature.SourceIp}",
                    $"{feature.SourceIp} contacted ASN {feature.Asn} that is new for this host baseline.",
                    0.5,
                    "medium",
                    $"Destination ASN {feature.Asn} not previously seen for this host"));
            }

            if (state.Confidence != "Low" && newPort && feature.DestinationPort.HasValue)
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "PortNovelty",
                    $"New destination port for {feature.SourceIp}",
                    $"{feature.SourceIp} used destination port {feature.DestinationPort.Value} that has not been observed for this host.",
                    0.44,
                    "medium",
                    $"Destination port {feature.DestinationPort.Value} not previously seen for this host"));
            }

            if (state.Confidence == "High" && (newJa4 || newHassh))
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "FingerprintNovelty",
                    $"Rare encrypted fingerprint for {feature.SourceIp}",
                    $"{feature.SourceIp} presented a new encrypted fingerprint that differs from prior host behavior.",
                    0.58,
                    "high",
                    newJa4 && !string.IsNullOrWhiteSpace(feature.Ja4)
                        ? $"JA4 fingerprint {feature.Ja4} not previously seen for this host"
                        : $"HASSH fingerprint {feature.Hassh} not previously seen for this host"));
            }

            if (state.Confidence != "Low" && newProcess && !string.IsNullOrWhiteSpace(feature.ProcessName))
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "ProcessNetworkAnomaly",
                    $"New process/network combination for {feature.SourceIp}",
                    $"{feature.ProcessName} has not previously been associated with this host's network activity profile.",
                    0.43,
                    "medium",
                    $"Process {feature.ProcessName} is new in the host baseline"));
            }

            var outboundThreshold = ZScoreThreshold(state.OutboundBytesStats, state.CurrentWindowOutboundBytes);
            if (state.Confidence == "High" && !state.EmittedCurrentWindowVolume && outboundThreshold > 4.0 && state.CurrentWindowOutboundBytes > state.OutboundBytesStats.Mean * 2)
            {
                state.EmittedCurrentWindowVolume = true;
                anomalies.Add(CreateSignal(
                    feature,
                    "TrafficVolumeAnomaly",
                    $"Outbound traffic spike from {feature.SourceIp}",
                    $"{feature.SourceIp} generated outbound traffic {Ratio(state.CurrentWindowOutboundBytes, state.OutboundBytesStats.Mean):0.0}x above its baseline in the current learning window.",
                    Math.Min(0.9, 0.45 + (outboundThreshold / 10.0)),
                    "high",
                    $"Outbound volume {Ratio(state.CurrentWindowOutboundBytes, state.OutboundBytesStats.Mean):0.0}x above baseline"));
            }

            return anomalies;
        }

        public IReadOnlyList<AnomalySignal> ObserveDetection(DetectionEvent evt, FlowFeature feature)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));
            if (feature == null) throw new ArgumentNullException(nameof(feature));
            if (string.IsNullOrWhiteSpace(feature.SourceIp))
                return Array.Empty<AnomalySignal>();

            feature.TimestampUtc = NormalizeTimestamp(feature.TimestampUtc);
            var anomalies = new List<AnomalySignal>();
            var state = GetHostState(feature.SourceIp);

            RotateWindowIfNeeded(state, feature.TimestampUtc, anomalies);
            state.LastSeenUtc = feature.TimestampUtc;
            _lastUpdatedUtc = feature.TimestampUtc;

            state.CurrentWindowRuleHits++;
            state.CurrentWindowSeverityWeightedAlerts += SeverityWeight(evt.Severity);

            if (evt.Severity >= SeverityLevel.High)
                state.CurrentWindowHighSeverityDetections++;

            if (state.Confidence != "Low" && evt.RuleId is "R003" or "R016")
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "ThreatIntelMatch",
                    $"Threat intelligence match for {feature.SourceIp}",
                    $"{feature.SourceIp} triggered threat intelligence or reputation rule {evt.RuleId}.",
                    0.72,
                    evt.Severity >= SeverityLevel.High ? "high" : "medium",
                    $"Rule {evt.RuleId} indicates a threat intelligence or reputation hit",
                    evt.RuleId));
            }

            if (!state.EmittedHighSeverityBurst
                && state.CurrentWindowHighSeverityDetections >= 3
                && state.Confidence != "Low")
            {
                state.EmittedHighSeverityBurst = true;
                anomalies.Add(CreateSignal(
                    feature,
                    "BehaviorChange",
                    $"High-severity rule burst for {feature.SourceIp}",
                    $"{feature.SourceIp} generated multiple high-severity rule detections within one correlation window.",
                    0.66,
                    "high",
                    $"{state.CurrentWindowHighSeverityDetections} high-severity detections occurred within the learning window",
                    evt.RuleId));
            }

            return anomalies;
        }

        public IReadOnlyList<BaselineSnapshot> GetSnapshots()
            => _hosts.Values.Select(state => state.ToSnapshot(_maxKnownValues)).ToArray();

        public BaselineStatus GetStatus()
        {
            var status = new BaselineStatus
            {
                ObservedHosts = _hosts.Count,
                LearningWindowMinutes = (int)_window.TotalMinutes,
                LastUpdatedUtc = _lastUpdatedUtc
            };

            foreach (var host in _hosts.Values)
            {
                switch (host.Confidence)
                {
                    case "High":
                        status.HighConfidenceHosts++;
                        break;
                    case "Medium":
                        status.MediumConfidenceHosts++;
                        break;
                    default:
                        status.LowConfidenceHosts++;
                        break;
                }
            }

            status.Confidence = status.HighConfidenceHosts > 0
                ? "High"
                : status.MediumConfidenceHosts > 0
                    ? "Medium"
                    : "Low";

            return status;
        }

        private HostState GetHostState(string hostId)
        {
            if (_hosts.TryGetValue(hostId, out var state))
                return state;

            if (_hosts.Count >= _maxHosts)
            {
                var oldest = _hosts.Values.OrderBy(h => h.LastSeenUtc).FirstOrDefault();
                if (oldest != null)
                    _hosts.Remove(oldest.HostId);
            }

            state = new HostState(hostId, _window);
            _hosts[hostId] = state;
            return state;
        }

        private void RotateWindowIfNeeded(HostState state, DateTime timestampUtc, List<AnomalySignal> anomalies)
        {
            if (state.CurrentWindowStartUtc == default)
            {
                state.CurrentWindowStartUtc = AlignWindow(timestampUtc, state.Window);
                state.FirstSeenUtc = timestampUtc;
                return;
            }

            if (timestampUtc < state.CurrentWindowStartUtc + _window)
                return;

            FinalizeWindow(state, anomalies);
            state.ResetWindow(AlignWindow(timestampUtc, state.Window));
        }

        private void FinalizeWindow(HostState state, List<AnomalySignal> anomalies)
        {
            if (state.CurrentWindowStartUtc == default)
                return;

            if (state.ObservationWindows >= 3 && state.Confidence != "Low")
            {
                EmitWindowAnomalies(state, anomalies);
            }

            state.OutboundBytesStats.Observe(state.CurrentWindowOutboundBytes);
            state.UniqueDestinationsStats.Observe(state.CurrentWindowUniqueDestinations.Count);
            state.UniquePortsStats.Observe(state.CurrentWindowUniquePorts.Count);
            state.DnsQueryStats.Observe(state.CurrentWindowDnsQueries);
            state.SeverityWeightedAlertStats.Observe(state.CurrentWindowSeverityWeightedAlerts);
            state.ObservationWindows++;
        }

        private static void EmitWindowAnomalies(HostState state, List<AnomalySignal> anomalies)
        {
            var feature = state.ToFeature();
            var bytesZ = ZScoreThreshold(state.OutboundBytesStats, state.CurrentWindowOutboundBytes);
            if (bytesZ >= 3.0 && state.CurrentWindowOutboundBytes > state.OutboundBytesStats.Mean)
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "TrafficVolumeAnomaly",
                    $"Outbound traffic spike from {state.HostId}",
                    $"{state.HostId} generated outbound traffic {Ratio(state.CurrentWindowOutboundBytes, state.OutboundBytesStats.Mean):0.0}x above its baseline in {(int)state.Window.TotalMinutes} minutes.",
                    Math.Min(0.92, 0.4 + (bytesZ / 8.0)),
                    bytesZ >= 5.0 ? "high" : "medium",
                    $"Outbound volume {Ratio(state.CurrentWindowOutboundBytes, state.OutboundBytesStats.Mean):0.0}x above baseline"));
            }

            var newDestinations = state.CurrentWindowNewDestinations.Count;
            if (newDestinations > 0 && state.Confidence != "Low")
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "DestinationNovelty",
                    $"New destination burst from {state.HostId}",
                    $"{state.HostId} contacted {newDestinations} new destinations in {(int)state.Window.TotalMinutes} minutes.",
                    Math.Min(0.85, 0.35 + (newDestinations / 20.0)),
                    newDestinations >= 10 ? "high" : "medium",
                    $"{newDestinations} new destinations observed in the learning window"));
            }

            var dnsZ = ZScoreThreshold(state.DnsQueryStats, state.CurrentWindowDnsQueries);
            if (dnsZ >= 3.0 && state.CurrentWindowDnsQueries > 0)
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "DnsAnomaly",
                    $"DNS activity anomaly from {state.HostId}",
                    $"{state.HostId} generated {state.CurrentWindowDnsQueries} DNS queries, which is elevated for this host.",
                    Math.Min(0.8, 0.35 + (dnsZ / 8.0)),
                    dnsZ >= 5.0 ? "high" : "medium",
                    $"DNS query volume increased to {state.CurrentWindowDnsQueries} within the learning window"));
            }

            var alertZ = ZScoreThreshold(state.SeverityWeightedAlertStats, state.CurrentWindowSeverityWeightedAlerts);
            if (alertZ >= 2.5 && state.CurrentWindowSeverityWeightedAlerts > 0)
            {
                anomalies.Add(CreateSignal(
                    feature,
                    "BehaviorChange",
                    $"Alert volume anomaly from {state.HostId}",
                    $"{state.HostId} generated a severity-weighted alert count above its baseline.",
                    Math.Min(0.84, 0.4 + (alertZ / 8.0)),
                    alertZ >= 5.0 ? "high" : "medium",
                    $"Severity-weighted alert count reached {state.CurrentWindowSeverityWeightedAlerts:0.0}"));
            }
        }

        private static double Ratio(double value, double mean)
        {
            var baseline = Math.Max(1.0, SanitizeNumber(mean));
            return value / baseline;
        }

        private static double ZScoreThreshold(RollingStats stats, double value)
        {
            var mean = SanitizeNumber(stats.Mean);
            var std = Math.Max(1.0, SanitizeNumber(stats.StdDev));
            var candidate = (SanitizeNumber(value) - mean) / std;
            return double.IsFinite(candidate) ? candidate : 0;
        }

        private static DateTime AlignWindow(DateTime timestampUtc, TimeSpan window)
        {
            var minutes = Math.Max(1, (int)Math.Round(window.TotalMinutes));
            return new DateTime(
                timestampUtc.Year,
                timestampUtc.Month,
                timestampUtc.Day,
                timestampUtc.Hour,
                (timestampUtc.Minute / minutes) * minutes,
                0,
                DateTimeKind.Utc);
        }

        private static double SeverityWeight(SeverityLevel severity)
            => severity switch
            {
                SeverityLevel.Critical => 4,
                SeverityLevel.High => 3,
                SeverityLevel.Medium => 2,
                SeverityLevel.Low => 1,
                _ => 0.5
            };

        private static void ObserveNovelty(HashSet<string> knownSet, string? value, HashSet<string> currentWindowSet, int maxKnownValues, out bool isNew)
        {
            isNew = false;
            if (string.IsNullOrWhiteSpace(value))
                return;

            var normalized = value.Trim();
            AddBounded(currentWindowSet, normalized, 256);
            if (knownSet.Contains(normalized))
                return;

            AddBounded(knownSet, normalized, Math.Max(32, maxKnownValues));
            isNew = true;
        }

        private static AnomalySignal CreateSignal(
            FlowFeature feature,
            string category,
            string title,
            string description,
            double score,
            string severity,
            params string[] reasons)
        {
            var signal = new AnomalySignal
            {
                CreatedUtc = feature.TimestampUtc,
                UpdatedUtc = feature.TimestampUtc,
                SourceIp = feature.SourceIp,
                DestinationIp = feature.DestinationIp,
                DestinationHost = feature.Domain,
                DestinationPort = feature.DestinationPort?.ToString(CultureInfo.InvariantCulture),
                Protocol = feature.Protocol,
                Category = category,
                Title = title,
                Description = description,
                Score = NormalizeScore(score),
                Severity = severity,
                Reasons = reasons.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                RelatedRuleIds = new[] { feature.RuleId }.Where(r => !string.IsNullOrWhiteSpace(r)).Cast<string>().ToList(),
                Tags = BuildTags(feature, category),
                Features = BuildFeatures(feature)
            };

            return signal;
        }

        private static double NormalizeScore(double score)
        {
            if (!double.IsFinite(score))
                return 0;

            return Math.Round(Math.Clamp(score, 0, 1), 2);
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

        private static double SanitizeNumber(double value)
            => double.IsFinite(value) ? value : 0;

        private static void AddBounded(HashSet<string> set, string? value, int maxEntries)
        {
            if (string.IsNullOrWhiteSpace(value) || maxEntries <= 0)
                return;

            if (set.Count >= maxEntries && !set.Contains(value))
                return;

            set.Add(value.Trim());
        }

        private static List<string> BuildTags(FlowFeature feature, string category)
        {
            var tags = new List<string> { category };
            if (!string.IsNullOrWhiteSpace(feature.ProcessName))
                tags.Add(feature.ProcessName);
            if (!string.IsNullOrWhiteSpace(feature.Protocol))
                tags.Add(feature.Protocol);
            if (feature.IsThreatFeedHit)
                tags.Add("threat-intel");
            return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static Dictionary<string, string> BuildFeatures(FlowFeature feature)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Direction"] = feature.Direction,
                ["HourOfDay"] = feature.HourOfDay.ToString(CultureInfo.InvariantCulture),
                ["DayOfWeek"] = feature.DayOfWeek.ToString()
            };

            if (!string.IsNullOrWhiteSpace(feature.ProcessName))
                values["ProcessName"] = feature.ProcessName;
            if (!string.IsNullOrWhiteSpace(feature.Country))
                values["Country"] = feature.Country;
            if (!string.IsNullOrWhiteSpace(feature.Asn))
                values["Asn"] = feature.Asn;
            if (!string.IsNullOrWhiteSpace(feature.Domain))
                values["Domain"] = feature.Domain;
            if (!string.IsNullOrWhiteSpace(feature.Ja4))
                values["Ja4"] = feature.Ja4;
            if (!string.IsNullOrWhiteSpace(feature.Hassh))
                values["Hassh"] = feature.Hassh;
            if (!string.IsNullOrWhiteSpace(feature.RuleSeverity))
                values["RuleSeverity"] = feature.RuleSeverity;

            return values;
        }

        private sealed class HostState
        {
            public HostState(string hostId, TimeSpan window)
            {
                HostId = hostId;
                Window = window;
            }

            public string HostId { get; }
            public TimeSpan Window { get; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public DateTime CurrentWindowStartUtc { get; set; }
            public int ObservationWindows { get; set; }

            public RollingStats OutboundBytesStats { get; } = new();
            public RollingStats UniqueDestinationsStats { get; } = new();
            public RollingStats UniquePortsStats { get; } = new();
            public RollingStats DnsQueryStats { get; } = new();
            public RollingStats SeverityWeightedAlertStats { get; } = new();

            public HashSet<string> KnownDestinations { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownPorts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownCountries { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownAsns { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownJa4Fingerprints { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownHasshFingerprints { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> KnownProcesses { get; } = new(StringComparer.OrdinalIgnoreCase);

            public double CurrentWindowOutboundBytes { get; set; }
            public HashSet<string> CurrentWindowUniqueDestinations { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowUniquePorts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public int CurrentWindowDnsQueries { get; set; }
            public double CurrentWindowSeverityWeightedAlerts { get; set; }
            public int CurrentWindowRuleHits { get; set; }
            public int CurrentWindowHighSeverityDetections { get; set; }
            public HashSet<string> CurrentWindowNewDestinations { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewCountries { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewAsns { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewPorts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewJa4 { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewHassh { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> CurrentWindowNewProcesses { get; } = new(StringComparer.OrdinalIgnoreCase);
            public bool EmittedCurrentWindowVolume { get; set; }
            public bool EmittedHighSeverityBurst { get; set; }

            public string Confidence => ObservationWindows switch
            {
                >= 12 => "High",
                >= 4 => "Medium",
                _ => "Low"
            };

            public void ResetWindow(DateTime nextWindowStartUtc)
            {
                CurrentWindowStartUtc = nextWindowStartUtc;
                CurrentWindowOutboundBytes = 0;
                CurrentWindowUniqueDestinations.Clear();
                CurrentWindowUniquePorts.Clear();
                CurrentWindowDnsQueries = 0;
                CurrentWindowSeverityWeightedAlerts = 0;
                CurrentWindowRuleHits = 0;
                CurrentWindowHighSeverityDetections = 0;
                CurrentWindowNewDestinations.Clear();
                CurrentWindowNewCountries.Clear();
                CurrentWindowNewAsns.Clear();
                CurrentWindowNewPorts.Clear();
                CurrentWindowNewJa4.Clear();
                CurrentWindowNewHassh.Clear();
                CurrentWindowNewProcesses.Clear();
                EmittedCurrentWindowVolume = false;
                EmittedHighSeverityBurst = false;
            }

            public FlowFeature ToFeature()
                => new()
                {
                    TimestampUtc = CurrentWindowStartUtc == default ? DateTime.UtcNow : CurrentWindowStartUtc,
                    SourceIp = HostId
                };

            public BaselineSnapshot ToSnapshot(int maxKnownValues)
            {
                return new BaselineSnapshot
                {
                    HostId = HostId,
                    FirstSeenUtc = FirstSeenUtc == default ? DateTime.UtcNow : FirstSeenUtc,
                    LastSeenUtc = LastSeenUtc == default ? DateTime.UtcNow : LastSeenUtc,
                    LastUpdatedUtc = LastSeenUtc == default ? DateTime.UtcNow : LastSeenUtc,
                    ObservationWindows = ObservationWindows,
                    Confidence = Confidence,
                    WindowMinutes = (int)Window.TotalMinutes,
                    OutboundBytesMean = OutboundBytesStats.Mean,
                    OutboundBytesStdDev = OutboundBytesStats.StdDev,
                    UniqueDestinationMean = UniqueDestinationsStats.Mean,
                    UniqueDestinationStdDev = UniqueDestinationsStats.StdDev,
                    UniquePortMean = UniquePortsStats.Mean,
                    UniquePortStdDev = UniquePortsStats.StdDev,
                    DnsQueryMean = DnsQueryStats.Mean,
                    DnsQueryStdDev = DnsQueryStats.StdDev,
                    SeverityWeightedAlertMean = SeverityWeightedAlertStats.Mean,
                    SeverityWeightedAlertStdDev = SeverityWeightedAlertStats.StdDev,
                    KnownDestinations = KnownDestinations.Take(maxKnownValues).ToList(),
                    KnownPorts = KnownPorts.Take(maxKnownValues).ToList(),
                    KnownCountries = KnownCountries.Take(maxKnownValues).ToList(),
                    KnownAsns = KnownAsns.Take(maxKnownValues).ToList(),
                    KnownJa4Fingerprints = KnownJa4Fingerprints.Take(maxKnownValues).ToList(),
                    KnownHasshFingerprints = KnownHasshFingerprints.Take(maxKnownValues).ToList(),
                    KnownProcesses = KnownProcesses.Take(maxKnownValues).ToList()
                };
            }

            public static HostState FromSnapshot(BaselineSnapshot snapshot, TimeSpan window)
            {
                var state = new HostState(snapshot.HostId, window)
                {
                    FirstSeenUtc = snapshot.FirstSeenUtc,
                    LastSeenUtc = snapshot.LastSeenUtc,
                    ObservationWindows = snapshot.ObservationWindows
                };

                state.OutboundBytesStats.Load(snapshot.ObservationWindows, snapshot.OutboundBytesMean, snapshot.OutboundBytesStdDev);
                state.UniqueDestinationsStats.Load(snapshot.ObservationWindows, snapshot.UniqueDestinationMean, snapshot.UniqueDestinationStdDev);
                state.UniquePortsStats.Load(snapshot.ObservationWindows, snapshot.UniquePortMean, snapshot.UniquePortStdDev);
                state.DnsQueryStats.Load(snapshot.ObservationWindows, snapshot.DnsQueryMean, snapshot.DnsQueryStdDev);
                state.SeverityWeightedAlertStats.Load(snapshot.ObservationWindows, snapshot.SeverityWeightedAlertMean, snapshot.SeverityWeightedAlertStdDev);

                foreach (var value in snapshot.KnownDestinations) state.KnownDestinations.Add(value);
                foreach (var value in snapshot.KnownPorts) state.KnownPorts.Add(value);
                foreach (var value in snapshot.KnownCountries) state.KnownCountries.Add(value);
                foreach (var value in snapshot.KnownAsns) state.KnownAsns.Add(value);
                foreach (var value in snapshot.KnownJa4Fingerprints) state.KnownJa4Fingerprints.Add(value);
                foreach (var value in snapshot.KnownHasshFingerprints) state.KnownHasshFingerprints.Add(value);
                foreach (var value in snapshot.KnownProcesses) state.KnownProcesses.Add(value);
                state.ResetWindow(DateTime.UtcNow);
                return state;
            }
        }

        private sealed class RollingStats
        {
            public int Count { get; private set; }
            public double Mean { get; private set; }
            public double M2 { get; private set; }
            public double StdDev => Count > 1 ? Math.Sqrt(M2 / (Count - 1)) : 0;

            public void Observe(double value)
            {
                if (!double.IsFinite(value))
                    return;

                Count++;
                var delta = value - Mean;
                Mean += delta / Count;
                var delta2 = value - Mean;
                M2 += delta * delta2;
            }

            public void Load(int count, double mean, double stdDev)
            {
                Count = Math.Max(0, count);
                Mean = SanitizeNumber(mean);
                var cleanStdDev = Math.Max(0, SanitizeNumber(stdDev));
                M2 = Count > 1 ? cleanStdDev * cleanStdDev * (Count - 1) : 0;
            }
        }
    }
}
