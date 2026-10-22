// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class IncidentTimelineBuilder
    {
        private const int MaxTimelineItems = 80;

        public void AddDetection(Incident incident, DetectionEvent evt)
        {
            if (incident == null || evt == null)
                return;

            var timestampUtc = NormalizeUtc(evt.Timestamp);
            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId("Detection", timestampUtc, incident.Id, evt.RuleId, evt.SourceIp, evt.DestinationIp, evt.DestinationHost, evt.Description),
                TimestampUtc = timestampUtc,
                Type = "Detection",
                Title = string.IsNullOrWhiteSpace(evt.RuleId) ? "Detection observed" : $"Rule {evt.RuleId} fired",
                Description = string.IsNullOrWhiteSpace(evt.Description) ? "A correlated detection event was observed." : evt.Description,
                Severity = NormalizeSeverity(evt.Severity.ToString()),
                SourceIp = evt.SourceIp,
                DestinationIp = evt.DestinationIp,
                DestinationHost = evt.DestinationHost,
                Category = CategorizeDetection(evt),
                Tags = Array.Empty<string>(),
                Details = CreateDetails(
                    ("RuleId", evt.RuleId),
                    ("Protocol", evt.Protocol),
                    ("DestinationPort", evt.DestinationPort?.ToString()),
                    ("ProcessName", evt.ProcessName))
            });
        }

        public void AddAnomaly(Incident incident, AnomalySignal anomaly)
        {
            if (incident == null || anomaly == null)
                return;

            var timestampUtc = NormalizeUtc(anomaly.UpdatedUtc == default ? anomaly.CreatedUtc : anomaly.UpdatedUtc);
            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId(IsMlSignal(anomaly) ? "MlSignal" : "Anomaly", timestampUtc, incident.Id, anomaly.Id, anomaly.Category, anomaly.Title),
                TimestampUtc = timestampUtc,
                Type = IsMlSignal(anomaly) ? "MlSignal" : "Anomaly",
                Title = string.IsNullOrWhiteSpace(anomaly.Title) ? "Anomaly observed" : anomaly.Title,
                Description = !string.IsNullOrWhiteSpace(anomaly.Description)
                    ? anomaly.Description
                    : anomaly.Reasons.FirstOrDefault() ?? "A correlated anomaly signal was observed.",
                Severity = NormalizeSeverity(anomaly.Severity),
                SourceIp = anomaly.SourceIp,
                DestinationIp = anomaly.DestinationIp,
                DestinationHost = anomaly.DestinationHost,
                Category = anomaly.Category,
                Tags = anomaly.Tags?.ToArray() ?? Array.Empty<string>(),
                Details = CreateDetails(
                    ("DestinationPort", anomaly.DestinationPort),
                    ("Protocol", anomaly.Protocol),
                    ("Score", anomaly.Score.ToString("0.00")),
                    ("TopReason", anomaly.Reasons.FirstOrDefault()))
            });
        }

        public void AddRiskChange(Incident incident, int? previousRiskScore, string? previousSeverity, string? reason = null)
        {
            if (incident == null)
                return;

            var currentRiskScore = incident.RiskScore;
            var currentSeverity = incident.Severity;

            if (!previousRiskScore.HasValue && string.IsNullOrWhiteSpace(previousSeverity))
            {
                AddItem(incident, new IncidentTimelineItem
                {
                    Id = BuildStableId("RiskChange", DateTime.UnixEpoch, incident.Id, currentRiskScore.ToString(), currentSeverity ?? string.Empty),
                    TimestampUtc = NormalizeUtc(incident.UpdatedUtc),
                    Type = "RiskChange",
                    Title = $"Initial risk assessed as {currentSeverity}",
                    Description = string.IsNullOrWhiteSpace(reason)
                        ? $"The correlated evidence produced an initial risk score of {currentRiskScore}/100."
                        : reason,
                    Severity = NormalizeSeverity(currentSeverity),
                    RiskScoreAfter = currentRiskScore,
                    SourceIp = incident.PrimarySourceIp,
                    DestinationIp = incident.PrimaryDestinationIp,
                    DestinationHost = incident.PrimaryDestinationHost,
                    Category = incident.Category,
                    Tags = Array.Empty<string>(),
                    Details = CreateDetails(("RiskScore", currentRiskScore.ToString()))
                });
                return;
            }

            var changedEnough = !previousRiskScore.HasValue
                || Math.Abs(currentRiskScore - previousRiskScore.Value) >= 8
                || !string.Equals(previousSeverity, currentSeverity, StringComparison.OrdinalIgnoreCase);

            if (!changedEnough)
                return;

            var direction = previousRiskScore.HasValue && currentRiskScore < previousRiskScore.Value ? "reduced" : "increased";
            var title = previousSeverity == null
                ? $"Risk assessed as {currentSeverity}"
                : $"Risk {direction} from {previousSeverity} to {currentSeverity}";

            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId("RiskChange", DateTime.UnixEpoch, incident.Id, previousRiskScore?.ToString() ?? "none", currentRiskScore.ToString(), previousSeverity ?? string.Empty, currentSeverity ?? string.Empty, reason ?? string.Empty),
                TimestampUtc = NormalizeUtc(incident.UpdatedUtc),
                Type = "RiskChange",
                Title = title,
                Description = string.IsNullOrWhiteSpace(reason)
                    ? $"The current correlated evidence changed the risk score to {currentRiskScore}/100."
                    : reason,
                Severity = NormalizeSeverity(currentSeverity),
                RiskScoreAfter = currentRiskScore,
                SourceIp = incident.PrimarySourceIp,
                DestinationIp = incident.PrimaryDestinationIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Tags = Array.Empty<string>(),
                Details = CreateDetails(
                    ("PreviousRiskScore", previousRiskScore?.ToString()),
                    ("RiskScore", currentRiskScore.ToString()))
            });
        }

        public void AddFeedback(Incident incident, IncidentFeedback feedback, IEnumerable<string>? appliedReasons = null)
        {
            if (incident == null || feedback == null)
                return;

            var normalizedType = NormalizeFeedbackType(feedback.FeedbackType);
            var type = feedback.FeedbackType switch
            {
                "SuppressSimilar" => "Suppression",
                "TrustDestinationForHost" or "TrustPortForHost" or "TrustProcessForHost" => "TrustRule",
                _ => "Feedback"
            };

            var description = appliedReasons?
                .FirstOrDefault(reason => !string.IsNullOrWhiteSpace(reason))
                ?? feedback.AnalystNote
                ?? DefaultFeedbackDescription(feedback);

            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId(type, feedback.CreatedUtc, incident.Id, feedback.FeedbackType, feedback.SourceIp, feedback.DestinationHost, feedback.DestinationIp, feedback.DestinationPort, feedback.ProcessName),
                TimestampUtc = NormalizeUtc(feedback.CreatedUtc),
                Type = type,
                Title = normalizedType,
                Description = description,
                Severity = type == "Feedback" && string.Equals(feedback.FeedbackType, "ConfirmedSuspicious", StringComparison.OrdinalIgnoreCase)
                    ? "high"
                    : "info",
                RiskScoreAfter = incident.RiskScore,
                SourceIp = feedback.SourceIp,
                DestinationIp = feedback.DestinationIp,
                DestinationHost = feedback.DestinationHost,
                Category = feedback.Category,
                Tags = feedback.Tags ?? Array.Empty<string>(),
                Details = CreateDetails(
                    ("FeedbackType", feedback.FeedbackType),
                    ("DestinationPort", feedback.DestinationPort),
                    ("ProcessName", feedback.ProcessName),
                    ("SuppressUntilUtc", feedback.SuppressUntilUtc?.ToString("o")))
            });
        }

        public void AddStatusChange(Incident incident, string? previousStatus, string? currentStatus)
        {
            if (incident == null || string.Equals(previousStatus, currentStatus, StringComparison.OrdinalIgnoreCase))
                return;

            var status = string.IsNullOrWhiteSpace(currentStatus) ? "New" : currentStatus;
            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId("StatusChange", DateTime.UnixEpoch, incident.Id, previousStatus ?? string.Empty, status),
                TimestampUtc = NormalizeUtc(incident.UpdatedUtc),
                Type = "StatusChange",
                Title = $"Incident status changed to {status}",
                Description = string.IsNullOrWhiteSpace(previousStatus)
                    ? $"The incident entered status {status}."
                    : $"The incident status changed from {previousStatus} to {status}.",
                Severity = NormalizeSeverity(incident.Severity),
                RiskScoreAfter = incident.RiskScore,
                SourceIp = incident.PrimarySourceIp,
                DestinationIp = incident.PrimaryDestinationIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Tags = Array.Empty<string>(),
                Details = CreateDetails(("Status", status))
            });
        }

        public void AddSummary(Incident incident, string? summary)
        {
            if (incident == null || string.IsNullOrWhiteSpace(summary))
                return;

            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId("Summary", DateTime.UnixEpoch, incident.Id, summary),
                TimestampUtc = NormalizeUtc(incident.UpdatedUtc),
                Type = "Summary",
                Title = "Incident summary updated",
                Description = summary.Trim(),
                Severity = "info",
                RiskScoreAfter = incident.RiskScore,
                SourceIp = incident.PrimarySourceIp,
                DestinationIp = incident.PrimaryDestinationIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Tags = Array.Empty<string>(),
                Details = CreateDetails(("SummaryLength", summary.Length.ToString()))
            });
        }

        public void AddRecommendedActions(Incident incident, IEnumerable<string>? actions)
        {
            if (incident == null || actions == null)
                return;

            foreach (var action in actions
                         .Where(action => !string.IsNullOrWhiteSpace(action))
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .Take(3))
            {
                AddItem(incident, new IncidentTimelineItem
                {
                    Id = BuildStableId("RecommendedAction", DateTime.UnixEpoch, incident.Id, action),
                    TimestampUtc = NormalizeUtc(incident.UpdatedUtc),
                    Type = "RecommendedAction",
                    Title = "Recommended action generated",
                    Description = action,
                    Severity = "info",
                    RiskScoreAfter = incident.RiskScore,
                    SourceIp = incident.PrimarySourceIp,
                    DestinationIp = incident.PrimaryDestinationIp,
                    DestinationHost = incident.PrimaryDestinationHost,
                    Category = incident.Category,
                    Tags = Array.Empty<string>(),
                    Details = CreateDetails(("Action", action))
                });
            }
        }

        public void AddDemoStep(Incident incident, string title, string description, DateTime timestampUtc, params string[] tags)
        {
            if (incident == null || string.IsNullOrWhiteSpace(title))
                return;

            AddItem(incident, new IncidentTimelineItem
            {
                Id = BuildStableId("DemoStep", timestampUtc, incident.Id, title, description),
                TimestampUtc = NormalizeUtc(timestampUtc),
                Type = "DemoStep",
                Title = title,
                Description = string.IsNullOrWhiteSpace(description) ? "A simulated demo step was added to the incident story." : description,
                Severity = "info",
                RiskScoreAfter = incident.RiskScore,
                SourceIp = incident.PrimarySourceIp,
                DestinationIp = incident.PrimaryDestinationIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                Tags = tags?.Where(tag => !string.IsNullOrWhiteSpace(tag)).ToArray() ?? Array.Empty<string>(),
                Details = CreateDetails(("Demo", "true"))
            });
        }

        public void NormalizeTimeline(Incident incident)
        {
            if (incident == null)
                return;

            incident.TimelineItems ??= new List<IncidentTimelineItem>();
            incident.TimelineItems = incident.TimelineItems
                .Where(item => item != null)
                .OrderBy(item => NormalizeUtc(item.TimestampUtc))
                .ThenBy(item => item.Type, StringComparer.OrdinalIgnoreCase)
                .GroupBy(item => item.Id, StringComparer.OrdinalIgnoreCase)
                .Select(group => NormalizeItem(group.First()))
                .TakeLast(MaxTimelineItems)
                .ToList();
        }

        private void AddItem(Incident incident, IncidentTimelineItem item)
        {
            incident.TimelineItems ??= new List<IncidentTimelineItem>();
            var normalizedItem = NormalizeItem(item);
            if (incident.TimelineItems.Any(existing => string.Equals(existing.Id, normalizedItem.Id, StringComparison.OrdinalIgnoreCase)))
                return;

            incident.TimelineItems.Add(normalizedItem);
            NormalizeTimeline(incident);
        }

        private static IncidentTimelineItem NormalizeItem(IncidentTimelineItem item)
        {
            item.Id = string.IsNullOrWhiteSpace(item.Id) ? Guid.NewGuid().ToString("N") : item.Id;
            item.TimestampUtc = NormalizeUtc(item.TimestampUtc);
            item.Type = string.IsNullOrWhiteSpace(item.Type) ? "Anomaly" : item.Type.Trim();
            item.Title ??= string.Empty;
            item.Description ??= string.Empty;
            item.Severity = NormalizeSeverity(item.Severity);
            item.Details ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            item.Tags = (item.Tags ?? Array.Empty<string>())
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return item;
        }

        private static Dictionary<string, string> CreateDetails(params (string Key, string? Value)[] pairs)
        {
            var details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in pairs)
            {
                if (!string.IsNullOrWhiteSpace(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                    details[pair.Key] = pair.Value!;
            }

            return details;
        }

        private static string NormalizeSeverity(string? severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
                return "info";

            var normalized = severity.Trim().ToLowerInvariant();
            return normalized switch
            {
                "critical" => "critical",
                "high" => "high",
                "medium" => "medium",
                "low" => "low",
                "info" => "info",
                _ => normalized
            };
        }

        private static string CategorizeDetection(DetectionEvent evt)
        {
            return evt.RuleId switch
            {
                "R003" or "R016" => "ThreatIntel",
                "R006" or "R022" or "R034" or "R048" => "DNS",
                "R008" or "R021" or "R036" => "Exfiltration",
                "R024" or "R025" or "R035" or "R037" or "R043" or "R049" => "EncryptedTraffic",
                _ => "Behavior"
            };
        }

        private static bool IsMlSignal(AnomalySignal anomaly)
            => string.Equals(anomaly.Category, "MlBehaviorAnomaly", StringComparison.OrdinalIgnoreCase)
               || anomaly.Tags.Any(tag => string.Equals(tag, "ml-assisted", StringComparison.OrdinalIgnoreCase));

        private static string NormalizeFeedbackType(string? feedbackType)
        {
            return feedbackType switch
            {
                "ConfirmedSuspicious" => "Analyst feedback: confirmed suspicious",
                "ExpectedBehavior" => "Analyst feedback: marked expected behavior",
                "FalsePositive" => "Analyst feedback: marked false positive",
                "SuppressSimilar" => "Suppression rule applied",
                "TrustDestinationForHost" => "Trust rule applied: destination trusted for host",
                "TrustPortForHost" => "Trust rule applied: port trusted for host",
                "TrustProcessForHost" => "Trust rule applied: process trusted for host",
                "AddNote" => "Analyst note saved",
                _ => "Analyst feedback applied"
            };
        }

        private static string DefaultFeedbackDescription(IncidentFeedback feedback)
        {
            return feedback.FeedbackType switch
            {
                "SuppressSimilar" => feedback.SuppressUntilUtc.HasValue
                    ? $"Similar incidents will be suppressed until {feedback.SuppressUntilUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm}."
                    : "A suppression rule was applied for similar incidents.",
                "TrustDestinationForHost" => "The destination was trusted for this host.",
                "TrustPortForHost" => "The destination port was trusted for this host.",
                "TrustProcessForHost" => "The process was trusted for this host.",
                "ConfirmedSuspicious" => "The analyst confirmed this pattern is suspicious.",
                "ExpectedBehavior" => "The analyst marked this pattern as expected behavior.",
                "FalsePositive" => "The analyst marked this pattern as a false positive.",
                "AddNote" => "The analyst added an investigation note.",
                _ => "The analyst updated the incident feedback state."
            };
        }

        private static DateTime NormalizeUtc(DateTime value)
        {
            if (value == default)
                return DateTime.UtcNow;

            return value.Kind switch
            {
                DateTimeKind.Utc => value,
                DateTimeKind.Local => value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
            };
        }

        private static string BuildStableId(string type, DateTime timestampUtc, params string?[] values)
        {
            var key = string.Join("|", new[] { type, NormalizeUtc(timestampUtc).ToString("o") }
                .Concat(values.Select(value => value?.Trim() ?? string.Empty)));

            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(key)))
                .ToLowerInvariant()[..24];
        }
    }
}
