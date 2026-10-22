// SPDX-License-Identifier: MIT
// File: Services/Timeline/AttackTimelineBuilder.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.EntityGraph;
using Carthago.Services.Feedback;
using Carthago.Services.Response;

namespace Carthago.Services.Timeline
{
    public sealed class AttackTimelineBuilder
    {
        public IReadOnlyList<TimelineEvent> BuildTimeline(
            IEnumerable<DetectionEvent> detections,
            IEnumerable<EntityRiskScore>? risks = null,
            IEnumerable<DetectionFeedback>? feedback = null,
            IEnumerable<ResponseAction>? responseActions = null,
            string? incidentId = null)
        {
            var items = new List<TimelineEvent>();
            foreach (var e in detections ?? Array.Empty<DetectionEvent>())
                items.Add(new TimelineEvent { TimestampUtc = e.TimestampUtc, Type = "Detection", EventId = e.EventId, IncidentId = incidentId ?? e.CorrelationId, Summary = $"{e.RuleId}: {e.Summary}", ContainsSensitiveEvidence = e.StructuredEvidence?.Items.Any(i => i.IsSensitive) == true });
            foreach (var r in risks ?? Array.Empty<EntityRiskScore>())
                items.Add(new TimelineEvent { TimestampUtc = r.CalculatedUtc, Type = "EntityRisk", EntityId = r.EntityId, Summary = $"Risk {r.Score} ({r.Level})" });
            foreach (var f in feedback ?? Array.Empty<DetectionFeedback>())
                items.Add(new TimelineEvent { TimestampUtc = f.TimestampUtc, Type = "Feedback", EventId = f.EventId, IncidentId = f.IncidentId, Summary = $"Feedback: {f.Verdict}" });
            foreach (var a in responseActions ?? Array.Empty<ResponseAction>())
                items.Add(new TimelineEvent { TimestampUtc = a.CreatedUtc, Type = "Response", EventId = a.SourceEventId, IncidentId = a.SourceIncidentId, EntityId = a.SourceEntityId, Summary = $"{a.ActionType}: {a.Reason}" });
            return items.OrderBy(i => i.TimestampUtc).ThenBy(i => i.Type, StringComparer.Ordinal).ToList();
        }

        public TimelineEvidenceBundle BuildBundle(Incident incident, IEnumerable<EntityRiskScore>? risks = null, IEnumerable<DetectionFeedback>? feedback = null, IEnumerable<ResponseAction>? responseActions = null, IEnumerable<string>? missingTelemetry = null)
        {
            var events = incident.RelatedEvents ?? new List<DetectionEvent>();
            var riskList = risks?.ToList() ?? new List<EntityRiskScore>();
            var fb = feedback?.ToList() ?? new List<DetectionFeedback>();
            var actions = responseActions?.ToList() ?? new List<ResponseAction>();
            return new TimelineEvidenceBundle
            {
                IncidentId = incident.IncidentId,
                Summary = incident.Summary ?? incident.Title,
                StoryType = incident.StoryType,
                RelatedEventIds = incident.RelatedEventIds.ToList(),
                RelatedRuleIds = incident.RelatedRuleIds.ToList(),
                RelatedEntityIds = riskList.Select(r => r.EntityId).ToList(),
                Detections = events.ToList(),
                EntityRiskScores = riskList,
                Feedback = fb,
                ResponseRecommendations = actions,
                MissingTelemetryWarnings = missingTelemetry?.ToList() ?? new List<string>(),
                Timeline = BuildTimeline(events, riskList, fb, actions, incident.IncidentId).ToList()
            };
        }
    }
}
