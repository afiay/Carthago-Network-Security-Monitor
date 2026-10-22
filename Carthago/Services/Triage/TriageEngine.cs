// SPDX-License-Identifier: MIT
// File: Services/Triage/TriageEngine.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.EntityGraph;

namespace Carthago.Services.Triage
{
    public sealed class TriageEngine
    {
        private readonly TriageOptions _options;
        public TriageEngine(TriageOptions? options = null) => _options = options ?? new TriageOptions();

        public TriageCase CreateCase(Incident incident, IReadOnlyList<EntityRiskScore>? riskScores = null)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));
            var events = incident.RelatedEvents ?? new List<DetectionEvent>();
            if (_options.RequireJournaledEvents && events.Any(e => e.DeliveryStatus != DetectionDeliveryStatus.Persisted && string.IsNullOrWhiteSpace(e.JournalPath)))
                throw new InvalidOperationException("Triage requires journaled DetectionEvents. Persist detections before triage.");

            var rules = events.Select(e => e.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var highest = events.Any(e => e.Severity == SeverityLevel.Critical) ? 4 : events.Any(e => e.Severity == SeverityLevel.High) ? 3 : events.Any(e => e.Severity == SeverityLevel.Medium) ? 2 : 1;
            var maxRisk = riskScores?.DefaultIfEmpty()?.Max(r => r?.Score ?? 0) ?? 0;
            var story = ResolveStory(incident.StoryType, rules);
            var confidence = Math.Clamp(events.DefaultIfEmpty().Average(e => e?.ConfidenceScore ?? 0.5) + maxRisk / 300.0, 0.05, 1.0);
            var severity = ResolveSeverity(story, highest, maxRisk, rules);

            var triage = new TriageCase
            {
                IncidentId = incident.IncidentId,
                SupportingEventIds = events.Select(e => e.EventId).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                AffectedEntityIds = riskScores?.Select(r => r.EntityId).Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>(),
                RelatedReplaySamples = rules.Select(r => $"Tests/RuleReplaySamples/**/*{r.ToLowerInvariant()}*.json").ToList(),
                Decision = new TriageDecision { Severity = severity, Confidence = confidence, LikelyStoryType = story }
            };

            foreach (var evt in events)
            {
                triage.Decision.Reasons.Add(new TriageReason
                {
                    Message = $"{evt.RuleId} contributed {evt.Severity} evidence: {evt.Summary}",
                    EventId = evt.EventId,
                    RuleId = evt.RuleId,
                    EntityId = string.IsNullOrWhiteSpace(evt.SourceIp) ? null : EntityGraphStore.EntityId(EntityNodeKind.Host, evt.SourceIp!)
                });
            }

            triage.Checklist.InvestigationSteps.Add("Open the related raw DetectionEvents and verify structured evidence before taking action.");
            triage.Checklist.InvestigationSteps.Add("Check whether the source host has related entity-risk reasons and recent baseline changes.");
            triage.Checklist.MissingEvidence.AddRange(events.Where(e => string.IsNullOrWhiteSpace(e.Protocol)).Select(e => $"{e.EventId}: protocol telemetry missing"));
            triage.Checklist.FalsePositiveHypotheses.Add("Expected administrative scan, vulnerability scanner, IoT device behavior, CDN/SaaS background traffic, or approved OT maintenance window.");
            triage.Checklist.TuningSuggestions.Add("If verified benign, add analyst feedback and profile/rule-specific threshold tuning rather than deleting the event.");

            triage.Decision.SafeActions.Add(new TriageRecommendation { SourceIncidentId = incident.IncidentId, Text = "Export evidence bundle for analyst review.", RequiresApproval = false });
            triage.Decision.SafeActions.Add(new TriageRecommendation { SourceIncidentId = incident.IncidentId, Text = "Add host to watchlist and increase monitoring sensitivity temporarily.", RequiresApproval = false });
            if (severity is TriageSeverity.HighPriority or TriageSeverity.CriticalImmediate)
                triage.Decision.ApprovalRequiredActions.Add(new TriageRecommendation { SourceIncidentId = incident.IncidentId, Text = "Recommend isolating affected host after human approval.", RequiresApproval = true });

            return triage;
        }

        private static AttackStoryType ResolveStory(AttackStoryType existing, HashSet<string> rules)
        {
            if (existing != AttackStoryType.None) return existing;
            if (Has(rules, "R084") && (Has(rules, "R090") || Has(rules, "R036"))) return AttackStoryType.ExploitToCallback;
            if (Has(rules, "R102") && (Has(rules, "R103") || Has(rules, "R036"))) return AttackStoryType.DnsC2Suspicion;
            if (Has(rules, "R017") && (Has(rules, "R073") || Has(rules, "R076"))) return AttackStoryType.ReconnaissanceToLateralMovement;
            if (Has(rules, "R113") && (Has(rules, "R114") || Has(rules, "R115"))) return AttackStoryType.IoTCompromiseSuspicion;
            if (Has(rules, "R120") && Has(rules, "R121")) return AttackStoryType.OTSegmentViolation;
            return AttackStoryType.None;
        }

        private static TriageSeverity ResolveSeverity(AttackStoryType story, int highestSeverity, int risk, HashSet<string> rules)
        {
            if (rules.Any(r => string.CompareOrdinal(r, "R050") >= 0 && string.CompareOrdinal(r, "R056") <= 0)) return TriageSeverity.PipelineHealthIssue;
            if (story is AttackStoryType.ExploitToCallback or AttackStoryType.LateralMovementToExfiltration || highestSeverity >= 4 || risk >= 75) return TriageSeverity.CriticalImmediate;
            if (story is AttackStoryType.DnsC2Suspicion or AttackStoryType.OTSegmentViolation || highestSeverity >= 3 || risk >= 50) return TriageSeverity.HighPriority;
            if (story != AttackStoryType.None || highestSeverity >= 2 || risk >= 25) return TriageSeverity.InvestigateSoon;
            return TriageSeverity.NeedsReview;
        }

        private static bool Has(HashSet<string> rules, string ruleId) => rules.Contains(ruleId);
    }
}
