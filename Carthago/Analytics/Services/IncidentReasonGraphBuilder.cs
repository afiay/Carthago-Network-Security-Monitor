// SPDX-License-Identifier: MIT
// File: Analytics/Services/IncidentReasonGraphBuilder.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class IncidentReasonGraphBuilder
    {
        public void AddDetection(Incident incident, DetectionEvent evt, string category, DateTime timestampUtc)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));
            if (evt == null) throw new ArgumentNullException(nameof(evt));

            incident.ReasonGraph ??= new IncidentReasonGraph();
            incident.CorrelationReasons ??= new List<IncidentCorrelationReason>();
            incident.RelatedEntities ??= new List<string>();

            var eventNode = NodeId("event", evt.EventId);
            var ruleNode = NodeId("rule", evt.RuleId);
            var sourceNode = NodeId("host", evt.SourceIp);
            var categoryNode = NodeId("category", category);
            var confidence = EffectiveConfidence(evt);
            var severityWeight = SeverityWeight(evt.Severity);
            var detectionWeight = Math.Clamp(Math.Max(confidence, severityWeight), 0.10, 1.0);

            incident.ReasonGraph.GetOrAddNode(eventNode, "Event", FirstNonEmpty(evt.RuleName, evt.RuleId, evt.EventId, "event"), detectionWeight);
            incident.ReasonGraph.GetOrAddNode(ruleNode, "Rule", FirstNonEmpty(evt.RuleId, evt.RuleName, "rule"), detectionWeight);
            incident.ReasonGraph.GetOrAddNode(sourceNode, "Host", FirstNonEmpty(evt.SourceIp, "unknown source"), detectionWeight);
            incident.ReasonGraph.GetOrAddNode(categoryNode, "Category", string.IsNullOrWhiteSpace(category) ? "Behavior" : category, 0.35);
            incident.ReasonGraph.AddEdge(sourceNode, eventNode, "produced", detectionWeight, evt.EventId);
            incident.ReasonGraph.AddEdge(eventNode, ruleNode, "matched_rule", detectionWeight, evt.EventId);
            incident.ReasonGraph.AddEdge(eventNode, categoryNode, "classified_as", 0.45, evt.EventId);

            AddEntity(incident, sourceNode);

            var target = FirstNonEmpty(evt.DestinationHost, evt.DestinationIp);
            if (!string.IsNullOrWhiteSpace(target))
            {
                var destinationNode = NodeId(IsIpAddressLike(target) ? "ip" : "host", target);
                incident.ReasonGraph.GetOrAddNode(destinationNode, IsIpAddressLike(target) ? "IpAddress" : "Host", target, 0.45);
                incident.ReasonGraph.AddEdge(eventNode, destinationNode, "targeted", 0.45, evt.EventId);
                AddEntity(incident, destinationNode);
            }

            foreach (var evidenceKey in ExtractEvidenceKeys(evt))
            {
                var evidenceNode = NodeId("evidence", evidenceKey);
                incident.ReasonGraph.GetOrAddNode(evidenceNode, "Evidence", evidenceKey, 0.30);
                incident.ReasonGraph.AddEdge(eventNode, evidenceNode, "has_evidence", 0.30, evt.EventId);
            }

            AddReason(incident, IncidentCorrelationReason.Create(
                code: "RULE_MATCH",
                description: $"{FirstNonEmpty(evt.RuleId, "Rule")} matched with {evt.ConfidenceLabel} confidence and {evt.Severity} severity.",
                weight: detectionWeight,
                timestampUtc: timestampUtc,
                eventId: evt.EventId,
                ruleId: evt.RuleId,
                category: category,
                sourceNodeId: sourceNode,
                targetNodeId: ruleNode,
                evidenceKeys: ExtractEvidenceKeys(evt)));

            if (incident.RelatedRuleIds.Count > 1)
            {
                AddReason(incident, IncidentCorrelationReason.Create(
                    code: "MULTI_RULE_CHAIN",
                    description: $"{incident.RelatedRuleIds.Count} distinct rules are linked to the same source/window.",
                    weight: Math.Clamp(0.25 + incident.RelatedRuleIds.Count * 0.08, 0, 0.9),
                    timestampUtc: timestampUtc,
                    eventId: evt.EventId,
                    ruleId: evt.RuleId,
                    category: category,
                    sourceNodeId: sourceNode,
                    targetNodeId: categoryNode));
            }

            RecalculateScores(incident);
        }

        public void AddAnomaly(Incident incident, AnomalySignal anomaly, string category, DateTime timestampUtc)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));
            if (anomaly == null) throw new ArgumentNullException(nameof(anomaly));

            incident.ReasonGraph ??= new IncidentReasonGraph();
            incident.CorrelationReasons ??= new List<IncidentCorrelationReason>();
            incident.RelatedEntities ??= new List<string>();

            var anomalyNode = NodeId("anomaly", anomaly.Id);
            var sourceNode = NodeId("host", anomaly.SourceIp);
            var categoryNode = NodeId("category", category);
            var weight = Math.Clamp(anomaly.Score, 0.15, 1.0);

            incident.ReasonGraph.GetOrAddNode(anomalyNode, "Anomaly", FirstNonEmpty(anomaly.Title, anomaly.Category, anomaly.Id, "anomaly"), weight);
            incident.ReasonGraph.GetOrAddNode(sourceNode, "Host", FirstNonEmpty(anomaly.SourceIp, "unknown source"), weight);
            incident.ReasonGraph.GetOrAddNode(categoryNode, "Category", string.IsNullOrWhiteSpace(category) ? "Behavior" : category, 0.35);
            incident.ReasonGraph.AddEdge(sourceNode, anomalyNode, "produced", weight, anomaly.Id);
            incident.ReasonGraph.AddEdge(anomalyNode, categoryNode, "classified_as", 0.45, anomaly.Id);
            AddEntity(incident, sourceNode);

            var target = FirstNonEmpty(anomaly.DestinationHost, anomaly.DestinationIp);
            if (!string.IsNullOrWhiteSpace(target))
            {
                var destinationNode = NodeId(IsIpAddressLike(target) ? "ip" : "host", target);
                incident.ReasonGraph.GetOrAddNode(destinationNode, IsIpAddressLike(target) ? "IpAddress" : "Host", target, 0.45);
                incident.ReasonGraph.AddEdge(anomalyNode, destinationNode, "targeted", 0.45, anomaly.Id);
                AddEntity(incident, destinationNode);
            }

            AddReason(incident, IncidentCorrelationReason.Create(
                code: "ANOMALY_SIGNAL",
                description: $"Anomaly signal {FirstNonEmpty(anomaly.Category, "Behavior")} contributed to this incident.",
                weight: weight,
                timestampUtc: timestampUtc,
                eventId: anomaly.Id,
                category: category,
                sourceNodeId: sourceNode,
                targetNodeId: anomalyNode,
                evidenceKeys: anomaly.Features.Keys));

            RecalculateScores(incident);
        }

        public void AddStory(Incident incident, AttackStoryType storyType, string reason, DateTime timestampUtc)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));
            if (storyType == AttackStoryType.None || string.IsNullOrWhiteSpace(reason))
                return;

            incident.ReasonGraph ??= new IncidentReasonGraph();
            incident.CorrelationReasons ??= new List<IncidentCorrelationReason>();

            var storyNode = NodeId("story", storyType.ToString());
            incident.ReasonGraph.GetOrAddNode(storyNode, "Story", storyType.ToString(), 0.85);
            foreach (var ruleId in incident.RelatedRuleIds.Take(20))
                incident.ReasonGraph.AddEdge(NodeId("rule", ruleId), storyNode, "supports_story", 0.65, ruleId);

            AddReason(incident, IncidentCorrelationReason.Create(
                code: "ATTACK_STORY",
                description: reason,
                weight: 0.85,
                timestampUtc: timestampUtc,
                category: storyType.ToString(),
                targetNodeId: storyNode));

            RecalculateScores(incident);
        }

        public IncidentCorrelationSummary BuildSummary(Incident incident)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));
            var graph = incident.ReasonGraph ?? new IncidentReasonGraph();
            var reasons = incident.CorrelationReasons ?? new List<IncidentCorrelationReason>();
            return new IncidentCorrelationSummary
            {
                IncidentId = incident.Id,
                StoryType = incident.StoryType.ToString(),
                StrengthScore = incident.CorrelationStrengthScore,
                ConfidenceScore = incident.ConfidenceScore,
                RelatedEventCount = incident.RelatedEventIds.Count,
                RelatedRuleCount = incident.RelatedRuleIds.Count,
                RelatedEntityCount = incident.RelatedEntities.Count,
                ReasonCount = reasons.Count,
                TopReasons = reasons.OrderByDescending(r => r.Weight).ThenByDescending(r => r.TimestampUtc).Take(5).Select(r => r.Description).ToArray(),
                ImportantEntities = graph.ImportantNodes(8).Where(n => n.Type is "Host" or "IpAddress").Select(n => n.Label).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            };
        }

        public void RecalculateScores(Incident incident)
        {
            if (incident == null) return;
            var distinctRuleCount = incident.RelatedRuleIds.Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var distinctEventCount = incident.RelatedEventIds.Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var categoryCount = incident.ReasonGraph?.Nodes.Count(n => string.Equals(n.Type, "Category", StringComparison.OrdinalIgnoreCase)) ?? 0;
            var storyBonus = incident.StoryType == AttackStoryType.None ? 0 : 0.20;
            var reasonScore = (incident.CorrelationReasons ?? new List<IncidentCorrelationReason>()).OrderByDescending(r => r.Weight).Take(5).Sum(r => r.Weight) / 5.0;
            var score = Math.Clamp(0.15 + distinctRuleCount * 0.10 + Math.Min(distinctEventCount, 8) * 0.04 + categoryCount * 0.03 + storyBonus + reasonScore * 0.25, 0, 1);
            incident.CorrelationStrengthScore = score;
            incident.ConfidenceScore = Math.Max(incident.ConfidenceScore, score);
        }

        private static void AddReason(Incident incident, IncidentCorrelationReason reason)
        {
            var exists = incident.CorrelationReasons.Any(existing =>
                string.Equals(existing.Code, reason.Code, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.EventId, reason.EventId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.RuleId, reason.RuleId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.Description, reason.Description, StringComparison.OrdinalIgnoreCase));
            if (exists)
                return;

            incident.CorrelationReasons.Add(reason);
            if (incident.CorrelationReasons.Count > 80)
                incident.CorrelationReasons.RemoveAt(0);
        }

        private static void AddEntity(Incident incident, string entityId)
        {
            if (string.IsNullOrWhiteSpace(entityId))
                return;
            if (!incident.RelatedEntities.Contains(entityId, StringComparer.OrdinalIgnoreCase))
                incident.RelatedEntities.Add(entityId);
            if (incident.RelatedEntities.Count > 60)
                incident.RelatedEntities.RemoveAt(0);
        }

        private static IEnumerable<string> ExtractEvidenceKeys(DetectionEvent evt)
        {
            if (evt.StructuredEvidence?.Items != null)
            {
                foreach (var item in evt.StructuredEvidence.Items)
                {
                    if (!string.IsNullOrWhiteSpace(item.Key))
                        yield return item.Key;
                }
            }

            if (string.IsNullOrWhiteSpace(evt.Evidence))
                yield break;

            foreach (var token in evt.Evidence.Split(new[] { ';', ',', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var key = token.Contains('=') ? token.Split('=', 2)[0] : token;
                if (!string.IsNullOrWhiteSpace(key))
                    yield return key.Trim();
            }
        }

        private static double EffectiveConfidence(DetectionEvent evt)
        {
            if (evt.ConfidenceScore > 0)
                return Math.Clamp(evt.ConfidenceScore, 0, 1);
            return evt.ConfidenceLabel switch
            {
                DetectionConfidenceLabel.High => 0.85,
                DetectionConfidenceLabel.Medium => 0.60,
                DetectionConfidenceLabel.Low => 0.35,
                _ => 0.20
            };
        }

        private static double SeverityWeight(SeverityLevel severity)
        {
            return severity switch
            {
                SeverityLevel.Critical => 1.0,
                SeverityLevel.High => 0.82,
                SeverityLevel.Medium => 0.55,
                SeverityLevel.Low => 0.30,
                _ => 0.15
            };
        }

        private static string NodeId(string type, string? value)
            => (string.IsNullOrWhiteSpace(type) ? "unknown" : type.Trim().ToLowerInvariant()) + ":" + (string.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim().ToLowerInvariant());

        private static string FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }
            return string.Empty;
        }

        private static bool IsIpAddressLike(string value)
            => value.Count(c => c == '.') == 3 || value.Contains(':');
    }
}
