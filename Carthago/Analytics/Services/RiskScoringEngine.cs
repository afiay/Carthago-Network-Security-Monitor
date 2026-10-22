// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class RiskScoringEngine
    {
        public void Score(Incident incident, IReadOnlyList<IncidentFeedback>? feedback = null)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));

            var reasons = new List<string>();
            var feedbackAppliedReasons = new List<string>();
            double score = 0;
            var feedbackEntries = feedback ?? Array.Empty<IncidentFeedback>();
            var anomalyScores = incident.RelatedAnomalies
                .Select(a => NormalizeScore(a.Score))
                .Where(value => value > 0)
                .ToArray();

            var maxSeverity = incident.RelatedEvents
                .Select(e => e.Severity)
                .DefaultIfEmpty(ParseSeverity(incident.Severity))
                .Max();

            score += maxSeverity switch
            {
                SeverityLevel.Critical => AddReason(reasons, 42, incident.RelatedEvents.FirstOrDefault(e => e.Severity == SeverityLevel.Critical)?.RuleId is string criticalRule && criticalRule.Length > 0
                    ? $"Critical rule matched: {criticalRule}"
                    : "Critical detection event present"),
                SeverityLevel.High => AddReason(reasons, 28, incident.RelatedEvents.FirstOrDefault(e => e.Severity == SeverityLevel.High)?.RuleId is string highRule && highRule.Length > 0
                    ? $"High severity rule matched: {highRule}"
                    : "High severity detection event present"),
                SeverityLevel.Medium => AddReason(reasons, 16, "Medium severity detection event present"),
                SeverityLevel.Low => AddReason(reasons, 8, "Low severity detection event present"),
                _ => 2
            };

            if (incident.RelatedEvents.Count > 1)
            {
                var eventPoints = Math.Min(18, (incident.RelatedEvents.Count - 1) * 4);
                score += AddReason(reasons, eventPoints, $"{incident.RelatedEvents.Count} related detections in the correlation window");
            }

            var maxAnomaly = anomalyScores.Length == 0 ? 0 : anomalyScores.Max();
            if (maxAnomaly > 0)
            {
                var anomalyPoints = Math.Min(22, maxAnomaly * 24.0);
                score += AddReason(reasons, anomalyPoints, $"Anomaly score peaked at {maxAnomaly:0.0}");
            }

            var distinctAnomalyCategories = incident.RelatedAnomalies
                .Select(a => a.Category)
                .Where(category => !string.IsNullOrWhiteSpace(category))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (distinctAnomalyCategories > 1)
            {
                score += AddReason(
                    reasons,
                    Math.Min(12, (distinctAnomalyCategories - 1) * 4),
                    $"{distinctAnomalyCategories} distinct anomaly types reinforced the same incident");
            }

            if (HasCategory(incident, "ThreatIntelMatch") || HasRule(incident, "R003") || HasRule(incident, "R016"))
                score += AddReason(reasons, 18, "Destination appears in threat intelligence or reputation data");

            var hasThreatIntel = HasCategory(incident, "ThreatIntelMatch") || HasRule(incident, "R003") || HasRule(incident, "R016");
            var hasCriticalEvidence = maxSeverity >= SeverityLevel.Critical;

            if (HasCategory(incident, "DestinationNovelty"))
                score += AddReason(reasons, 10, "Destination not previously seen for this host");

            if (HasCategory(incident, "GeoAnomaly"))
                score += AddReason(reasons, 8, "Destination country not previously seen for this host");

            if (HasReasonContaining(incident, "asn"))
                score += AddReason(reasons, 8, "Destination ASN not previously seen for this host");

            if (HasCategory(incident, "PortNovelty"))
                score += AddReason(reasons, 7, "Destination port not previously seen for this host");

            if (HasReasonContaining(incident, "process"))
                score += AddReason(reasons, 7, "Unusual process/network relationship observed");

            if (HasCategory(incident, "FingerprintNovelty"))
                score += AddReason(reasons, 6, "Rare encrypted fingerprint observed");

            if (HasCategory(incident, "TrafficVolumeAnomaly"))
                score += AddReason(reasons, 11, "Outbound volume exceeded the learned baseline");

            var mlSignal = incident.RelatedAnomalies
                .FirstOrDefault(anomaly => string.Equals(anomaly.Category, "MlBehaviorAnomaly", StringComparison.OrdinalIgnoreCase));
            if (mlSignal != null)
            {
                var mlScore = ParseMlScore(mlSignal);
                if (mlScore > 0)
                {
                    var mlPoints = Math.Min(14, mlScore / 8.0);
                    score += AddReason(reasons, mlPoints, $"ML-assisted anomaly score: {mlScore:0}/100");
                }

                var mlReason = mlSignal.Reasons.FirstOrDefault(reason =>
                    reason.Contains("ML.NET detected", StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(mlReason))
                    score += AddReason(reasons, 4, mlReason);
            }

            if (HasRule(incident, "R046") || HasRule(incident, "R047"))
                score += AddReason(reasons, 9, "Administrative or credential-sensitive traffic pattern observed");

            if (incident.Category.Contains("Cisco", StringComparison.OrdinalIgnoreCase)
                && maxSeverity >= SeverityLevel.High)
            {
                score += AddReason(reasons, 8, "High-severity Cisco or infrastructure signal present");
            }

            if (HasTag(incident, "allowlisted"))
                score -= AddReason(reasons, 14, "Known allowlisted admin flow reduced score");

            ApplyFeedbackAdjustments(
                incident,
                feedbackEntries,
                reasons,
                feedbackAppliedReasons,
                ref score,
                hasThreatIntel,
                hasCriticalEvidence);

            if (incident.RelatedEvents.Count == 0
                && incident.RelatedAnomalies.Count <= 1
                && maxAnomaly > 0
                && maxAnomaly < 0.55)
            {
                score = Math.Min(score, 55);
            }

            if (incident.RelatedEvents.Count == 0
                && incident.RelatedAnomalies.Count > 0
                && incident.RelatedAnomalies.All(anomaly => string.Equals(anomaly.Category, "MlBehaviorAnomaly", StringComparison.OrdinalIgnoreCase)))
            {
                score = Math.Min(score, 45);
            }

            if (!double.IsFinite(score))
                score = 0;

            incident.RiskScore = Math.Clamp((int)Math.Round(score, MidpointRounding.AwayFromZero), 0, 100);
            incident.FeedbackAppliedReasons = feedbackAppliedReasons
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var finalReasons = reasons
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var selectedReasons = finalReasons.Take(6).ToList();
            if (mlSignal != null)
            {
                var mlReason = finalReasons.FirstOrDefault(reason =>
                    reason.Contains("ML-assisted", StringComparison.OrdinalIgnoreCase)
                    || reason.Contains("ML.NET detected", StringComparison.OrdinalIgnoreCase));

                if (!string.IsNullOrWhiteSpace(mlReason)
                    && !selectedReasons.Any(reason => string.Equals(reason, mlReason, StringComparison.OrdinalIgnoreCase)))
                {
                    if (selectedReasons.Count >= 6)
                        selectedReasons[^1] = mlReason;
                    else
                        selectedReasons.Add(mlReason);
                }
            }

            var feedbackReason = feedbackAppliedReasons.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(feedbackReason)
                && !selectedReasons.Any(reason => string.Equals(reason, feedbackReason, StringComparison.OrdinalIgnoreCase)))
            {
                if (selectedReasons.Count >= 6)
                    selectedReasons[^1] = feedbackReason;
                else
                    selectedReasons.Add(feedbackReason);
            }

            incident.RiskReasons = selectedReasons;
            incident.Severity = incident.RiskScore switch
            {
                <= 30 => "Low",
                <= 60 => "Medium",
                <= 80 => "High",
                _ => "Critical"
            };
        }

        private static void ApplyFeedbackAdjustments(
            Incident incident,
            IReadOnlyList<IncidentFeedback> feedbackEntries,
            List<string> reasons,
            List<string> feedbackAppliedReasons,
            ref double score,
            bool hasThreatIntel,
            bool hasCriticalEvidence)
        {
            incident.IsSuppressed = false;
            incident.SuppressedUntilUtc = null;

            if (feedbackEntries.Count == 0)
                return;

            var nowUtc = DateTime.UtcNow;
            var confirmedCount = feedbackEntries.Count(entry => string.Equals(entry.FeedbackType, "ConfirmedSuspicious", StringComparison.OrdinalIgnoreCase));
            var expectedCount = feedbackEntries.Count(entry => string.Equals(entry.FeedbackType, "ExpectedBehavior", StringComparison.OrdinalIgnoreCase));
            var falsePositiveCount = feedbackEntries.Count(entry => string.Equals(entry.FeedbackType, "FalsePositive", StringComparison.OrdinalIgnoreCase));
            var hasMitigatingFeedback = false;
            var suppression = feedbackEntries
                .Where(entry => string.Equals(entry.FeedbackType, "SuppressSimilar", StringComparison.OrdinalIgnoreCase))
                .Where(entry => !entry.SuppressUntilUtc.HasValue || entry.SuppressUntilUtc.Value > nowUtc)
                .OrderByDescending(entry => entry.SuppressUntilUtc ?? DateTime.MinValue)
                .FirstOrDefault();

            if (confirmedCount > 0)
            {
                score += AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    Math.Min(18, 8 + ((confirmedCount - 1) * 4)),
                    "Risk increased: similar behavior previously confirmed suspicious.");
            }

            if (expectedCount > 0)
            {
                hasMitigatingFeedback = true;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    Math.Min(24, 12 + ((expectedCount - 1) * 4)),
                    "Risk reduced: similar behavior marked expected by analyst.");
            }

            if (falsePositiveCount > 0)
            {
                hasMitigatingFeedback = true;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    Math.Min(24, 12 + ((falsePositiveCount - 1) * 4)),
                    "Risk reduced: similar behavior previously marked false positive.");
            }

            if (suppression != null)
            {
                hasMitigatingFeedback = true;
                incident.IsSuppressed = true;
                incident.SuppressedUntilUtc = suppression.SuppressUntilUtc;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    18,
                    $"Risk reduced: suppression active until {suppression.SuppressUntilUtc?.ToLocalTime():yyyy-MM-dd HH:mm}.");
            }

            if (HasCategory(incident, "DestinationNovelty")
                && feedbackEntries.Any(entry => string.Equals(entry.FeedbackType, "TrustDestinationForHost", StringComparison.OrdinalIgnoreCase)))
            {
                hasMitigatingFeedback = true;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    10,
                    "Risk reduced: destination trusted for this host.");
            }

            if (HasCategory(incident, "PortNovelty")
                && feedbackEntries.Any(entry => string.Equals(entry.FeedbackType, "TrustPortForHost", StringComparison.OrdinalIgnoreCase)))
            {
                hasMitigatingFeedback = true;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    8,
                    "Risk reduced: destination port trusted for this host.");
            }

            if ((HasReasonContaining(incident, "process") || HasCategory(incident, "ProcessNetworkAnomaly"))
                && feedbackEntries.Any(entry => string.Equals(entry.FeedbackType, "TrustProcessForHost", StringComparison.OrdinalIgnoreCase)))
            {
                hasMitigatingFeedback = true;
                score -= AddFeedbackReason(
                    reasons,
                    feedbackAppliedReasons,
                    7,
                    "Risk reduced: process trusted for this host.");
            }

            if (hasThreatIntel || hasCriticalEvidence)
            {
                if (hasMitigatingFeedback)
                    score = Math.Min(score, hasCriticalEvidence ? 80 : 75);
                score = Math.Max(score, 40);
                if (incident.IsSuppressed)
                {
                    AddFeedbackReason(
                        reasons,
                        feedbackAppliedReasons,
                        0,
                        "Trusted or suppressed pattern matched, but threat intelligence or critical evidence keeps the incident visible.");
                }
            }
            else if (incident.IsSuppressed)
            {
                score = Math.Min(score, 25);
            }

            if (!double.IsFinite(score))
                score = 0;
        }

        private static bool HasRule(Incident incident, string ruleId)
            => incident.RelatedEvents.Any(e => string.Equals(e.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
            || incident.RelatedAnomalies.Any(a => a.RelatedRuleIds.Any(r => string.Equals(r, ruleId, StringComparison.OrdinalIgnoreCase)));

        private static bool HasCategory(Incident incident, string category)
            => incident.RelatedAnomalies.Any(a => string.Equals(a.Category, category, StringComparison.OrdinalIgnoreCase));

        private static bool HasTag(Incident incident, string tag)
            => incident.Tags.Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase))
            || incident.RelatedAnomalies.Any(a => a.Tags.Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase)));

        private static bool HasReasonContaining(Incident incident, string token)
            => incident.RelatedAnomalies.Any(a => a.Reasons.Any(r => r.Contains(token, StringComparison.OrdinalIgnoreCase)));

        private static SeverityLevel ParseSeverity(string? severity)
        {
            if (Enum.TryParse<SeverityLevel>(severity, true, out var parsed))
                return parsed;
            return SeverityLevel.Low;
        }

        private static double AddReason(List<string> reasons, double value, string reason)
        {
            if (!string.IsNullOrWhiteSpace(reason))
                reasons.Add(reason);
            return value;
        }

        private static double AddFeedbackReason(List<string> reasons, List<string> feedbackAppliedReasons, double value, string reason)
        {
            if (!string.IsNullOrWhiteSpace(reason))
            {
                reasons.Add(reason);
                feedbackAppliedReasons.Add(reason);
            }

            return value;
        }

        private static double NormalizeScore(double value)
            => double.IsFinite(value) ? Math.Clamp(value, 0, 1) : 0;

        private static double ParseMlScore(AnomalySignal anomaly)
        {
            if (anomaly.Features.TryGetValue("MlScore", out var value)
                && double.TryParse(value, out var parsed)
                && double.IsFinite(parsed))
            {
                return Math.Clamp(parsed, 0, 100);
            }

            return Math.Clamp(NormalizeScore(anomaly.Score) * 100.0, 0, 100);
        }
    }
}
