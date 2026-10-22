// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class IncidentCorrelationEngine
    {
        private readonly TimeSpan _window;
        private readonly TimeSpan _resolvedReopenQuietPeriod;
        private readonly IncidentTimelineBuilder _timelineBuilder;
        private readonly IncidentReasonGraphBuilder _reasonGraphBuilder;
        private readonly Dictionary<string, Incident> _openIncidents = new(StringComparer.OrdinalIgnoreCase);

        public IncidentCorrelationEngine(TimeSpan? window = null, IEnumerable<Incident>? existingIncidents = null, IncidentTimelineBuilder? timelineBuilder = null, IncidentReasonGraphBuilder? reasonGraphBuilder = null)
        {
            _window = window ?? TimeSpan.FromMinutes(15);
            _resolvedReopenQuietPeriod = TimeSpan.FromMinutes(Math.Max(2, _window.TotalMinutes / 3));
            _timelineBuilder = timelineBuilder ?? new IncidentTimelineBuilder();
            _reasonGraphBuilder = reasonGraphBuilder ?? new IncidentReasonGraphBuilder();

            if (existingIncidents == null)
                return;

            foreach (var incident in existingIncidents)
            {
                if (incident == null || string.IsNullOrWhiteSpace(incident.CorrelationKey))
                    continue;

                if (incident.LastSeenUtc < DateTime.UtcNow - _window)
                    continue;

                _openIncidents[incident.CorrelationKey] = incident;
            }
        }

        public CorrelationResult Correlate(DetectionEvent evt)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));

            var timestampUtc = NormalizeTimestamp(evt.Timestamp);
            var category = Categorize(evt);
            var input = new CorrelationInput(
                TimestampUtc: timestampUtc,
                SourceIp: NormalizeKeyPart(evt.SourceIp, "unknown"),
                DestinationIp: NormalizeKeyPart(evt.DestinationIp, "unknown"),
                DestinationHost: NormalizeKeyPart(evt.DestinationHost, null),
                Category: category,
                Family: CorrelationFamilyForCategory(category),
                Fingerprint: NormalizeKeyPart(evt.RuleId, null));

            var result = GetOrCreateIncident(input);
            RefreshIncidentMetadata(result.Incident, input);
            RegisterObservation(result.Incident, timestampUtc);
            AddEvent(result.Incident, evt);
            _reasonGraphBuilder.AddDetection(result.Incident, evt, category, timestampUtc);
            var storyUpdate = UpdateAttackStory(result.Incident);
            if (storyUpdate.StoryType != AttackStoryType.None)
                _reasonGraphBuilder.AddStory(result.Incident, storyUpdate.StoryType, storyUpdate.Reason, timestampUtc);
            _timelineBuilder.AddDetection(result.Incident, evt);
            AddEvidence(result.Incident, $"{evt.RuleId}: {evt.Description}");
            AddTag(result.Incident, category);
            return result;
        }

        public CorrelationResult Correlate(AnomalySignal anomaly)
        {
            if (anomaly == null) throw new ArgumentNullException(nameof(anomaly));

            var timestampUtc = NormalizeTimestamp(anomaly.UpdatedUtc == default ? anomaly.CreatedUtc : anomaly.UpdatedUtc);
            var category = Categorize(anomaly);
            anomaly.Features.TryGetValue("ProcessName", out var processName);
            anomaly.Features.TryGetValue("Ja4", out var ja4);
            anomaly.Features.TryGetValue("Hassh", out var hassh);

            var input = new CorrelationInput(
                TimestampUtc: timestampUtc,
                SourceIp: NormalizeKeyPart(anomaly.SourceIp, "unknown"),
                DestinationIp: NormalizeKeyPart(anomaly.DestinationIp, "unknown"),
                DestinationHost: NormalizeKeyPart(anomaly.DestinationHost, null),
                Category: category,
                Family: CorrelationFamilyForCategory(category),
                Fingerprint: FirstNonEmpty(processName, ja4, hassh));

            var result = GetOrCreateIncident(input);
            RefreshIncidentMetadata(result.Incident, input);
            RegisterObservation(result.Incident, timestampUtc);
            AddAnomaly(result.Incident, anomaly);
            _reasonGraphBuilder.AddAnomaly(result.Incident, anomaly, category, timestampUtc);
            var storyUpdate = UpdateAttackStory(result.Incident);
            if (storyUpdate.StoryType != AttackStoryType.None)
                _reasonGraphBuilder.AddStory(result.Incident, storyUpdate.StoryType, storyUpdate.Reason, timestampUtc);
            _timelineBuilder.AddAnomaly(result.Incident, anomaly);
            AddEvidence(result.Incident, anomaly.Title);
            AddTags(result.Incident, anomaly.Tags);
            return result;
        }

        public bool UpdateStatus(string incidentId, string status)
        {
            var incident = _openIncidents.Values.FirstOrDefault(i => string.Equals(i.Id, incidentId, StringComparison.OrdinalIgnoreCase));
            if (incident == null)
                return false;

            var previousStatus = incident.Status;
            incident.Status = NormalizeStatus(status);
            incident.UpdatedUtc = DateTime.UtcNow;
            _timelineBuilder.AddStatusChange(incident, previousStatus, incident.Status);
            return true;
        }

        public IReadOnlyList<Incident> GetIncidents()
            => _openIncidents.Values
                .OrderByDescending(i => i.RiskScore)
                .ThenByDescending(i => i.UpdatedUtc)
                .ToArray();

        private CorrelationResult GetOrCreateIncident(CorrelationInput input)
        {
            var keys = BuildCorrelationKeys(input);
            foreach (var key in keys)
            {
                if (!_openIncidents.TryGetValue(key, out var existing))
                    continue;

                if (!CanReuseIncident(existing, input.TimestampUtc))
                    continue;

                existing.CorrelationKey = key;
                return new CorrelationResult(existing, false);
            }

            var fallback = FindRecentFamilyMatch(input);
            if (fallback != null)
                return new CorrelationResult(fallback, false);

            var incident = CreateIncident(keys[0], input, input.TimestampUtc);
            _openIncidents[keys[0]] = incident;
            return new CorrelationResult(incident, true);
        }

        private Incident? FindRecentFamilyMatch(CorrelationInput input)
        {
            return _openIncidents.Values
                .Where(incident => CanReuseIncident(incident, input.TimestampUtc))
                .Where(incident => string.Equals(NormalizeKeyPart(incident.PrimarySourceIp, "unknown"), input.SourceIp, StringComparison.OrdinalIgnoreCase))
                .Where(incident => string.Equals(CorrelationFamilyForCategory(incident.Category), input.Family, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(incident => MatchPriority(incident, input))
                .ThenByDescending(incident => incident.LastSeenUtc)
                .FirstOrDefault();
        }

        private int MatchPriority(Incident incident, CorrelationInput input)
        {
            var score = 0;
            var incidentTarget = NormalizeKeyPart(incident.PrimaryDestinationHost ?? incident.PrimaryDestinationIp, null);
            if (!string.IsNullOrWhiteSpace(incidentTarget)
                && string.Equals(incidentTarget, input.TargetKey, StringComparison.OrdinalIgnoreCase))
            {
                score += 10;
            }

            if (string.Equals(incident.Category, input.Category, StringComparison.OrdinalIgnoreCase))
                score += 4;

            if (SameBucket(incident.LastSeenUtc, input.TimestampUtc))
                score += 3;

            if (!string.IsNullOrWhiteSpace(input.Fingerprint)
                && incident.Tags.Any(tag => string.Equals(tag, input.Fingerprint, StringComparison.OrdinalIgnoreCase)))
            {
                score += 2;
            }

            if (string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase))
                score -= 8;

            return score;
        }

        private bool CanReuseIncident(Incident incident, DateTime timestampUtc)
        {
            if (incident.LastSeenUtc < timestampUtc - _window)
                return false;

            if (!string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase))
                return true;

            return timestampUtc <= incident.LastSeenUtc + _resolvedReopenQuietPeriod;
        }

        private bool SameBucket(DateTime left, DateTime right)
            => BucketFor(left) == BucketFor(right);

        private Incident CreateIncident(string correlationKey, CorrelationInput input, DateTime createdUtc)
        {
            return new Incident
            {
                Id = ComputeStableId(correlationKey, createdUtc),
                CorrelationKey = correlationKey,
                Title = BuildTitle(input.Category, input.SourceIp, input.TargetKey),
                Category = input.Category,
                FirstSeenUtc = createdUtc,
                CreatedUtc = createdUtc,
                UpdatedUtc = createdUtc,
                LastSeenUtc = createdUtc,
                PrimarySourceIp = input.SourceIp,
                PrimaryDestinationIp = NullIfUnknown(input.DestinationIp),
                PrimaryDestinationHost = NullIfUnknown(input.DestinationHost),
                Status = "New",
                OccurrenceCount = 0,
                CorrelationVersion = 1,
                ReasonGraph = new IncidentReasonGraph()
            };
        }

        private void RefreshIncidentMetadata(Incident incident, CorrelationInput input)
        {
            incident.PrimarySourceIp ??= NullIfUnknown(input.SourceIp);

            if (string.IsNullOrWhiteSpace(incident.PrimaryDestinationHost) && !string.IsNullOrWhiteSpace(input.DestinationHost))
                incident.PrimaryDestinationHost = input.DestinationHost;

            if (string.IsNullOrWhiteSpace(incident.PrimaryDestinationIp) && !string.IsNullOrWhiteSpace(input.DestinationIp))
                incident.PrimaryDestinationIp = input.DestinationIp;

            if (CategoryPriority(input.Category) > CategoryPriority(incident.Category))
                incident.Category = input.Category;

            incident.Title = BuildTitle(incident.Category, incident.PrimarySourceIp, incident.PrimaryDestinationHost ?? incident.PrimaryDestinationIp);
        }

        private static void RegisterObservation(Incident incident, DateTime lastSeenUtc)
        {
            incident.OccurrenceCount = Math.Max(1, incident.OccurrenceCount + 1);
            incident.LastSeenUtc = lastSeenUtc;
            incident.UpdatedUtc = DateTime.UtcNow;
        }

        private static void AddEvent(Incident incident, DetectionEvent evt)
        {
            if (string.IsNullOrWhiteSpace(evt.EventId))
                evt.EventId = Guid.NewGuid().ToString("N");

            evt.CorrelationId = incident.Id;
            incident.PrimaryRuleId ??= evt.RuleId;
            incident.CorrelationReason ??= $"Grouped by source/category/window: {incident.CorrelationKey}";

            if (!string.IsNullOrWhiteSpace(evt.RuleId) && !incident.RelatedRuleIds.Contains(evt.RuleId, StringComparer.OrdinalIgnoreCase))
                incident.RelatedRuleIds.Add(evt.RuleId);

            if (!string.IsNullOrWhiteSpace(evt.EventId) && !incident.RelatedEventIds.Contains(evt.EventId, StringComparer.OrdinalIgnoreCase))
                incident.RelatedEventIds.Add(evt.EventId);

            var exists = incident.RelatedEvents.Any(existing =>
                (!string.IsNullOrWhiteSpace(existing.EventId) && string.Equals(existing.EventId, evt.EventId, StringComparison.OrdinalIgnoreCase))
                || (string.Equals(existing.RuleId, evt.RuleId, StringComparison.OrdinalIgnoreCase)
                    && existing.Timestamp == evt.Timestamp
                    && string.Equals(existing.SourceIp, evt.SourceIp, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.DestinationIp, evt.DestinationIp, StringComparison.OrdinalIgnoreCase)
                    && existing.DestinationPort == evt.DestinationPort));

            if (exists)
                return;

            incident.RelatedEvents.Add(evt);
            if (incident.RelatedEvents.Count > 40)
                incident.RelatedEvents.RemoveAt(0);

            incident.EvidenceSummary = string.Join("; ", incident.RelatedEvents.Select(e => $"{e.RuleId}: {e.Description}").Take(20));
        }

        private static StoryUpdateResult UpdateAttackStory(Incident incident)
        {
            var rules = incident.RelatedRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
            AttackStoryType story = AttackStoryType.None;
            string? reason = null;

            bool Has(params string[] ids) => ids.Any(rules.Contains);
            int CountRange(int start, int end) => rules.Count(ruleId => TryParseRuleNumber(ruleId, out var number) && number >= start && number <= end);

            if (Has("R017", "R001") && Has("R073", "R074", "R075", "R076", "R078"))
            {
                story = AttackStoryType.ReconnaissanceToLateralMovement;
                reason = "Reconnaissance followed by remote-service/lateral-movement behavior.";
            }
            else if (Has("R084", "R085", "R086", "R089") && Has("R090", "R093", "R036"))
            {
                story = AttackStoryType.ExploitToCallback;
                reason = "Exploit/payload indicator followed by callback, command execution, or outbound transfer.";
            }
            else if (Has("R073", "R074", "R075", "R076", "R078") && Has("R036", "R104", "R105", "R107", "R108"))
            {
                story = AttackStoryType.LateralMovementToExfiltration;
                reason = "Lateral movement indicators followed by upload/exfiltration indicators.";
            }
            else if (Has("R102", "R103") && Has("R036", "R094", "R095"))
            {
                story = AttackStoryType.DnsC2Suspicion;
                reason = "DNS tunneling/beaconing indicators correlated with suspicious DNS or egress.";
            }
            else if (Has("R113", "R114", "R115") || (Has("R117", "R118") && Has("R119")) || CountRange(233, 242) >= 2 || CountRange(473, 492) >= 2)
            {
                story = AttackStoryType.IoTCompromiseSuspicion;
                reason = "IoT/OT protocol misuse, enumeration, write, or exposure indicators observed together.";
            }
            else if (Has("R120") && Has("R121", "R122"))
            {
                story = AttackStoryType.OTSegmentViolation;
                reason = "OT protocol traffic observed outside approved segment or from unexpected host.";
            }
            else if (Has("R104", "R105", "R107", "R108", "R112") || CountRange(243, 257) >= 2 || CountRange(493, 512) >= 2)
            {
                story = CountRange(493, 512) >= 2 ? AttackStoryType.DataLossStagingSuspicion : AttackStoryType.CloudExfiltrationSuspicion;
                reason = "Upload, staging, archive, sensitive extension, or cloud/SaaS transfer indicators correlated for the same entity.";
            }
            else if (CountRange(273, 292) >= 2 || Has("R274", "R280", "R282"))
            {
                story = AttackStoryType.IdentityCompromiseSuspicion;
                reason = "Identity, VPN, OAuth, MFA, token, or authentication-abuse indicators correlated for the same entity.";
            }
            else if (CountRange(293, 312) >= 2 || Has("R295", "R297", "R299", "R302"))
            {
                story = AttackStoryType.KubernetesCompromiseSuspicion;
                reason = "Kubernetes/container API, exec, token, registry, or runtime-socket indicators correlated.";
            }
            else if (CountRange(353, 372) >= 2 || Has("R356", "R357", "R358", "R365"))
            {
                story = AttackStoryType.DevOpsSupplyChainSuspicion;
                reason = "CI/CD, source control, package registry, build system, or secret exposure indicators correlated.";
            }
            else if (CountRange(393, 412) >= 2 || Has("R393", "R394", "R395", "R396"))
            {
                story = AttackStoryType.MalwareC2Suspicion;
                reason = "Malware/C2 beacon, staging, user-agent, URI, or tunnel indicators correlated.";
            }
            else if (CountRange(413, 432) >= 2 || Has("R413", "R414", "R415", "R416"))
            {
                story = AttackStoryType.NetworkApplianceExposureIncident;
                reason = "Network appliance management, exploit probe, or exposure indicators correlated.";
            }
            else if (CountRange(433, 452) >= 2 || Has("R437", "R438", "R439", "R440"))
            {
                story = AttackStoryType.DatabaseExposureIncident;
                reason = "Database service exposure, administrative command, dump, or risky access indicators correlated.";
            }
            else if (CountRange(513, 528) >= 2 || Has("R516", "R517", "R518", "R519"))
            {
                story = AttackStoryType.EvasionTunnelSuspicion;
                reason = "Tunnel, proxy, DNS/ICMP/QUIC evasion, or covert-channel indicators correlated.";
            }
            else if (Has("R050", "R051", "R052", "R053", "R054", "R055", "R056") || CountRange(529, 544) >= 1)
            {
                story = AttackStoryType.DetectionPipelineHealthIncident;
                reason = "Detection pipeline reliability or platform-health rule triggered.";
            }

            if (story == AttackStoryType.None || string.IsNullOrWhiteSpace(reason))
                return new StoryUpdateResult(AttackStoryType.None, string.Empty);

            incident.StoryType = story;
            incident.CorrelationReason = reason;
            incident.ConfidenceScore = Math.Max(incident.ConfidenceScore, Math.Min(1.0, 0.45 + Math.Min(incident.RelatedRuleIds.Count, 5) * 0.10));
            if (!incident.Tags.Any(t => string.Equals(t, story.ToString(), StringComparison.OrdinalIgnoreCase)))
                incident.Tags.Add(story.ToString());
            incident.EvidenceSummary = string.Join("; ", incident.RelatedEvents.Select(e => $"{e.RuleId}: {e.Description}").Take(20));
            return new StoryUpdateResult(story, reason);
        }

        private void AddAnomaly(Incident incident, AnomalySignal anomaly)
        {
            var exists = incident.RelatedAnomalies.Any(existing =>
                string.Equals(existing.Id, anomaly.Id, StringComparison.OrdinalIgnoreCase)
                || (string.Equals(existing.Category, anomaly.Category, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.SourceIp, anomaly.SourceIp, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.DestinationIp, anomaly.DestinationIp, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.DestinationHost, anomaly.DestinationHost, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.DestinationPort, anomaly.DestinationPort, StringComparison.OrdinalIgnoreCase)
                    && BucketFor(existing.CreatedUtc) == BucketFor(anomaly.CreatedUtc)));

            if (exists)
                return;

            incident.RelatedAnomalies.Add(anomaly);
            if (incident.RelatedAnomalies.Count > 50)
                incident.RelatedAnomalies.RemoveAt(0);
        }

        private static void AddEvidence(Incident incident, string? evidence)
        {
            if (string.IsNullOrWhiteSpace(evidence))
                return;

            if (incident.Evidence.Any(existing => string.Equals(existing, evidence, StringComparison.OrdinalIgnoreCase)))
                return;

            incident.Evidence.Add(evidence);
            if (incident.Evidence.Count > 12)
                incident.Evidence.RemoveAt(0);
        }

        private static void AddTag(Incident incident, string tag)
        {
            if (string.IsNullOrWhiteSpace(tag))
                return;

            if (incident.Tags.Any(existing => string.Equals(existing, tag, StringComparison.OrdinalIgnoreCase)))
                return;

            incident.Tags.Add(tag);
        }

        private static void AddTags(Incident incident, IEnumerable<string> tags)
        {
            foreach (var tag in tags)
                AddTag(incident, tag);
        }

        private string[] BuildCorrelationKeys(CorrelationInput input)
        {
            var bucket = BucketFor(input.TimestampUtc).ToString("yyyyMMddHHmm");
            var hostKey = string.Join("|", input.SourceIp, input.Family, bucket);
            var targetKey = string.IsNullOrWhiteSpace(input.TargetKey)
                ? hostKey
                : string.Join("|", input.SourceIp, input.Family, input.TargetKey, bucket);

            return targetKey == hostKey
                ? new[] { hostKey }
                : new[] { targetKey, hostKey };
        }

        private DateTime BucketFor(DateTime timestampUtc)
        {
            var minutes = Math.Max(1, (int)_window.TotalMinutes);
            return new DateTime(
                timestampUtc.Year,
                timestampUtc.Month,
                timestampUtc.Day,
                timestampUtc.Hour,
                (timestampUtc.Minute / minutes) * minutes,
                0,
                DateTimeKind.Utc);
        }

        private static string BuildTitle(string category, string? sourceIp, string? target)
        {
            var actor = string.IsNullOrWhiteSpace(sourceIp) ? "unknown host" : sourceIp;
            return category switch
            {
                "ThreatIntel" when !string.IsNullOrWhiteSpace(target) => $"Suspicious outbound behavior from {actor} to {target}",
                "ThreatIntel" => $"Suspicious outbound behavior from {actor}",
                "Reconnaissance" => $"Suspicious scanning activity from {actor}",
                "CiscoSyslog" => $"Cisco device anomaly observed for {actor}",
                "DNS" => $"Suspicious outbound behavior from {actor}",
                "Exfiltration" => $"Suspicious outbound behavior from {actor}",
                "EncryptedTraffic" => $"Suspicious encrypted traffic from {actor}",
                _ when !string.IsNullOrWhiteSpace(target) => $"Suspicious outbound behavior from {actor} to {target}",
                _ => $"Suspicious outbound behavior from {actor}"
            };
        }

        private static string ComputeStableId(string correlationKey, DateTime createdUtc)
        {
            using var sha256 = SHA256.Create();
            var input = $"{correlationKey}|{createdUtc:yyyyMMddHHmm}";
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes).ToLowerInvariant()[..24];
        }

        private static string Categorize(AnomalySignal anomaly)
        {
            if (string.IsNullOrWhiteSpace(anomaly.Category))
                return "Behavior";

            return anomaly.Category switch
            {
                "DnsAnomaly" => "DNS",
                "ThreatIntelMatch" => "ThreatIntel",
                "ReputationHit" => "ThreatIntel",
                "TrafficVolumeAnomaly" => "Exfiltration",
                "GeoAnomaly" => "Geo",
                "FingerprintNovelty" => "EncryptedTraffic",
                "PortNovelty" => "Behavior",
                "ProcessNetworkAnomaly" => "Behavior",
                "DestinationNovelty" => "Behavior",
                "MlBehaviorAnomaly" => "Behavior",
                "BehaviorChange" => "Behavior",
                "CiscoSyslogAnomaly" => "CiscoSyslog",
                _ => "Behavior"
            };
        }

        private static string Categorize(DetectionEvent evt)
        {
            if (TryParseRuleNumber(evt.RuleId, out var number))
            {
                if (number is 6 or 22 or 34 or 48 or >= 94 and <= 103 or >= 181 and <= 192)
                    return "DNS";
                if (number is 1 or 17 or 30 or >= 57 and <= 72 or >= 453 and <= 472)
                    return "Reconnaissance";
                if (number is 3 or 16 or >= 193 and <= 212 or >= 393 and <= 412)
                    return "ThreatIntel";
                if (number is 8 or 21 or 36 or >= 104 and <= 112 or >= 243 and <= 257 or >= 493 and <= 512)
                    return "Exfiltration";
                if (number is 24 or 25 or 35 or 37 or 43 or 49 or >= 123 and <= 142)
                    return "EncryptedTraffic";
                if (number is 10 or 39)
                    return "Geo";
                if (number >= 233 && number <= 242)
                    return "IoT/OT";
                if (number >= 258 && number <= 272)
                    return "EvasionInfrastructure";
                if (number >= 273 && number <= 292)
                    return "Identity";
                if (number >= 293 && number <= 312)
                    return "KubernetesContainer";
                if (number >= 313 && number <= 332)
                    return "EmailCollaboration";
                if (number >= 333 && number <= 352)
                    return "ActiveDirectoryWindows";
                if (number >= 353 && number <= 372)
                    return "DevOpsSupplyChain";
                if (number >= 373 && number <= 392)
                    return "CloudInfrastructure";
                if (number >= 413 && number <= 432)
                    return "NetworkApplianceExposure";
                if (number >= 433 && number <= 452)
                    return "DatabaseServiceExposure";
                if (number >= 473 && number <= 492)
                    return "OT/ICS";
                if (number >= 513 && number <= 528)
                    return "EvasionTunnel";
                if (number >= 529 && number <= 544)
                    return "PlatformHealth";
            }

            return "Behavior";
        }

        private static string CorrelationFamilyForCategory(string category)
        {
            return category switch
            {
                "Reconnaissance" => "Reconnaissance",
                "CiscoSyslog" => "CiscoOperations",
                "PlatformHealth" => "PlatformHealth",
                "Identity" => "IdentityCompromise",
                "KubernetesContainer" => "WorkloadCompromise",
                "DevOpsSupplyChain" => "SupplyChain",
                "NetworkApplianceExposure" => "EdgeExposure",
                "DatabaseServiceExposure" => "DataStoreExposure",
                "IoT/OT" or "OT/ICS" => "IndustrialIoT",
                _ => "HostCompromise"
            };
        }

        private static int CategoryPriority(string? category)
        {
            return category switch
            {
                "ThreatIntel" => 9,
                "Exfiltration" => 8,
                "Identity" => 8,
                "MalwareC2" => 8,
                "KubernetesContainer" => 7,
                "DevOpsSupplyChain" => 7,
                "DatabaseServiceExposure" => 7,
                "NetworkApplianceExposure" => 7,
                "EvasionTunnel" => 7,
                "EncryptedTraffic" => 6,
                "DNS" => 5,
                "IoT/OT" => 5,
                "OT/ICS" => 5,
                "PlatformHealth" => 4,
                "Geo" => 2,
                "Behavior" => 1,
                _ => 0
            };
        }

        private static string NormalizeStatus(string? status)
        {
            if (string.Equals(status, "Resolved", StringComparison.OrdinalIgnoreCase))
                return "Resolved";
            if (string.Equals(status, "Acknowledged", StringComparison.OrdinalIgnoreCase))
                return "Acknowledged";
            return "New";
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

        private static string NormalizeKeyPart(string? value, string? fallback)
            => string.IsNullOrWhiteSpace(value) ? (fallback ?? string.Empty) : value.Trim();

        private static string? NullIfUnknown(string? value)
            => string.IsNullOrWhiteSpace(value) || string.Equals(value, "unknown", StringComparison.OrdinalIgnoreCase) ? null : value;

        private static string? FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }

            return null;
        }


        private static bool TryParseRuleNumber(string? ruleId, out int number)
        {
            number = 0;
            if (string.IsNullOrWhiteSpace(ruleId))
                return false;

            var digits = new string(ruleId.Where(char.IsDigit).ToArray());
            return digits.Length > 0 && int.TryParse(digits, out number);
        }

        private readonly record struct StoryUpdateResult(AttackStoryType StoryType, string Reason);

        private readonly record struct CorrelationInput(
            DateTime TimestampUtc,
            string SourceIp,
            string DestinationIp,
            string? DestinationHost,
            string Category,
            string Family,
            string? Fingerprint)
        {
            public string? TargetKey => FirstNonEmpty(DestinationHost, DestinationIp);
        }
    }

    public readonly record struct CorrelationResult(Incident Incident, bool IsNew);
}
