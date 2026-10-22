// SPDX-License-Identifier: MIT
// File: Services/Timeline/TimelineModels.cs
using System;
using System.Collections.Generic;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.EntityGraph;
using Carthago.Services.Feedback;
using Carthago.Services.Response;

namespace Carthago.Services.Timeline
{
    public sealed class TimelineEvent
    {
        public DateTime TimestampUtc { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
        public string? EventId { get; set; }
        public string? IncidentId { get; set; }
        public string? EntityId { get; set; }
        public bool ContainsSensitiveEvidence { get; set; }
    }

    public sealed class TimelineEvidenceBundle
    {
        public string BundleId { get; set; } = Guid.NewGuid().ToString("N");
        public string? IncidentId { get; set; }
        public string Summary { get; set; } = string.Empty;
        public AttackStoryType StoryType { get; set; }
        public List<string> RelatedEventIds { get; set; } = new();
        public List<string> RelatedRuleIds { get; set; } = new();
        public List<string> RelatedEntityIds { get; set; } = new();
        public List<TimelineEvent> Timeline { get; set; } = new();
        public List<DetectionEvent> Detections { get; set; } = new();
        public List<EntityRiskScore> EntityRiskScores { get; set; } = new();
        public List<DetectionFeedback> Feedback { get; set; } = new();
        public List<ResponseAction> ResponseRecommendations { get; set; } = new();
        public List<string> MissingTelemetryWarnings { get; set; } = new();
    }
}
