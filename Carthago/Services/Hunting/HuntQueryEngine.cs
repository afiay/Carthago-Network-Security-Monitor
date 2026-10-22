// SPDX-License-Identifier: MIT
// File: Services/Hunting/HuntQueryEngine.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.EntityGraph;

namespace Carthago.Services.Hunting
{
    public sealed class HuntQueryEngine
    {
        public HuntQueryResult Execute(HuntQuery query, IEnumerable<DetectionEvent> detections, IEnumerable<Incident>? incidents = null, IEnumerable<EntityRiskScore>? risks = null)
        {
            IEnumerable<DetectionEvent> ev = detections ?? Array.Empty<DetectionEvent>();
            if (!string.IsNullOrWhiteSpace(query.RuleId)) ev = ev.Where(e => string.Equals(e.RuleId, query.RuleId, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(query.SourceIp)) ev = ev.Where(e => string.Equals(e.SourceIp, query.SourceIp, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(query.DestinationIp)) ev = ev.Where(e => string.Equals(e.DestinationIp, query.DestinationIp, StringComparison.OrdinalIgnoreCase));
            if (query.MinConfidence.HasValue) ev = ev.Where(e => e.ConfidenceScore >= query.MinConfidence.Value);
            if (query.SuppressionStatus.HasValue) ev = ev.Where(e => e.SuppressionStatus == query.SuppressionStatus.Value);
            if (query.ExternalSinkStatus.HasValue) ev = ev.Where(e => e.ExternalDeliveryStatus == query.ExternalSinkStatus.Value);
            if (!string.IsNullOrWhiteSpace(query.EntityContains)) ev = ev.Where(e => (e.SourceIp ?? "").Contains(query.EntityContains!, StringComparison.OrdinalIgnoreCase) || (e.DestinationIp ?? "").Contains(query.EntityContains!, StringComparison.OrdinalIgnoreCase) || (e.DestinationHost ?? "").Contains(query.EntityContains!, StringComparison.OrdinalIgnoreCase));

            IEnumerable<Incident> inc = incidents ?? Array.Empty<Incident>();
            if (query.StoryType.HasValue) inc = inc.Where(i => i.StoryType == query.StoryType.Value);
            if (query.MinRiskScore.HasValue)
            {
                var risky = (risks ?? Array.Empty<EntityRiskScore>()).Where(r => r.Score >= query.MinRiskScore.Value).Select(r => r.EntityId).ToHashSet(StringComparer.OrdinalIgnoreCase);
                ev = ev.Where(e => risky.Contains(EntityGraphStore.EntityId(EntityNodeKind.Host, e.SourceIp ?? e.EventId)));
            }

            var detectionsList = ev.ToList();
            var incidentList = inc.ToList();
            return new HuntQueryResult
            {
                Detections = detectionsList,
                Incidents = incidentList,
                SourceIds = detectionsList.Select(e => e.EventId).Concat(incidentList.Select(i => i.IncidentId)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            };
        }
    }
}
