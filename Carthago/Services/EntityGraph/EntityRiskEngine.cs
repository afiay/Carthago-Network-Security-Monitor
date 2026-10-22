// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityRiskEngine.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
using Carthago.Services.Feedback;

namespace Carthago.Services.EntityGraph
{
    public sealed class EntityRiskEngine
    {
        public IReadOnlyList<EntityRiskScore> ScoreDetections(
            IEnumerable<DetectionEvent> detections,
            IEnumerable<DetectionFeedback>? feedback = null,
            DateTime? nowUtc = null)
        {
            var now = nowUtc ?? DateTime.UtcNow;
            var falsePositiveEvents = (feedback ?? Array.Empty<DetectionFeedback>())
                .Where(f => f.Verdict == DetectionFeedbackVerdict.FalsePositive)
                .Select(f => f.EventId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var byEntity = new Dictionary<string, List<EntityRiskReason>>(StringComparer.OrdinalIgnoreCase);
            foreach (var evt in detections ?? Array.Empty<DetectionEvent>())
            {
                var entity = string.IsNullOrWhiteSpace(evt.SourceIp)
                    ? EntityGraphStore.EntityId(EntityNodeKind.DetectionEvent, evt.EventId)
                    : EntityGraphStore.EntityId(EntityNodeKind.Host, evt.SourceIp!);

                var severity = evt.Severity switch
                {
                    SeverityLevel.Critical => 35,
                    SeverityLevel.High => 24,
                    SeverityLevel.Medium => 14,
                    SeverityLevel.Low => 6,
                    _ => 2
                };
                var confidence = Math.Clamp(evt.ConfidenceScore, 0, 1);
                var confidenceBonus = (int)Math.Round(confidence * 12);
                var matureBonus = string.Equals(evt.RuleMaturityAtDetection, "Stable", StringComparison.OrdinalIgnoreCase) ? 4 : 0;
                var threatBonus = evt.RuleId is "R003" or "R016" ? 12 : 0;
                var lateralBonus = IsAny(evt.RuleId, "R017", "R030", "R073", "R074", "R075", "R076", "R077", "R078", "R079", "R080", "R081", "R082", "R083") ? 10 : 0;
                var exfilBonus = IsAny(evt.RuleId, "R008", "R036", "R104", "R105", "R106", "R107", "R108", "R112") ? 10 : 0;
                var suppressPenalty = evt.SuppressionStatus == DetectionSuppressionStatus.Suppressed ? -8 : 0;
                var fpPenalty = falsePositiveEvents.Contains(evt.EventId) ? -20 : 0;
                var ageHours = Math.Max(0, (now - evt.TimestampUtc).TotalHours);
                var decay = ageHours switch { > 168 => 0.25, > 72 => 0.50, > 24 => 0.75, _ => 1.0 };
                var delta = (int)Math.Round(Math.Max(0, severity + confidenceBonus + matureBonus + threatBonus + lateralBonus + exfilBonus + suppressPenalty + fpPenalty) * decay);
                if (delta <= 0) continue;

                if (!byEntity.TryGetValue(entity, out var reasons))
                    byEntity[entity] = reasons = new List<EntityRiskReason>();
                reasons.Add(new EntityRiskReason
                {
                    EntityId = entity,
                    ScoreDelta = delta,
                    RuleId = evt.RuleId,
                    EvidenceEventId = evt.EventId,
                    TimestampUtc = evt.TimestampUtc == default ? now : evt.TimestampUtc,
                    Reason = $"Triggered {evt.RuleId} ({evt.RuleName}) with {evt.ConfidenceLabel} confidence and {evt.Severity} severity."
                });
            }

            return byEntity.Select(kv =>
            {
                var score = Math.Clamp(kv.Value.Sum(r => r.ScoreDelta), 0, 100);
                return new EntityRiskScore { EntityId = kv.Key, Score = score, Level = EntityRiskScore.LevelFor(score), Reasons = kv.Value.OrderByDescending(r => r.ScoreDelta).ToList(), CalculatedUtc = now };
            }).OrderByDescending(r => r.Score).ToList();
        }

        private static bool IsAny(string? value, params string[] expected) => expected.Contains(value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
    }
}
