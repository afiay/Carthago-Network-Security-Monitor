// SPDX-License-Identifier: MIT
// File: Analytics/Models/Incident.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using Carthago.Models;
using LiteDB;

namespace Carthago.Analytics.Models
{
    public sealed class Incident
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string IncidentId { get => Id; set => Id = value; }
        public string? PrimaryRuleId { get; set; }
        public List<string> RelatedRuleIds { get; set; } = new();
        public List<string> RelatedEventIds { get; set; } = new();
        public string? CorrelationReason { get; set; }
        public string? EvidenceSummary { get; set; }
        public AttackStoryType StoryType { get; set; } = AttackStoryType.None;
        public double ConfidenceScore { get; set; }
        public double CorrelationStrengthScore { get; set; }
        public int CorrelationVersion { get; set; } = 1;
        public List<string> RelatedEntities { get; set; } = new();
        public List<IncidentCorrelationReason> CorrelationReasons { get; set; } = new();
        public IncidentReasonGraph ReasonGraph { get; set; } = new();

        public string Title { get; set; } = "";
        public string Severity { get; set; } = "medium";
        public int RiskScore { get; set; }
        public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public string? PrimarySourceIp { get; set; }
        public string? PrimaryDestinationIp { get; set; }
        public string? PrimaryDestinationHost { get; set; }
        public string Category { get; set; } = "General";
        public string Status { get; set; } = "New";
        public string? CorrelationKey { get; set; }

        public string? Summary { get; set; }
        public bool IsAnalyzing { get; set; }
        public int OccurrenceCount { get; set; } = 1;

        public List<DetectionEvent> RelatedEvents { get; set; } = new();
        public List<AnomalySignal> RelatedAnomalies { get; set; } = new();
        public List<string> Evidence { get; set; } = new();
        public List<string> RecommendedActions { get; set; } = new();
        public List<string> Tags { get; set; } = new();
        public List<string> RiskReasons { get; set; } = new();
        public List<IncidentTimelineItem> TimelineItems { get; set; } = new();
        public string? AnalystFeedbackType { get; set; }
        public string? AnalystNote { get; set; }
        public List<string> FeedbackAppliedReasons { get; set; } = new();
        public DateTime? SuppressedUntilUtc { get; set; }
        public bool IsSuppressed { get; set; }
        public DateTime? LastFeedbackUtc { get; set; }

        [BsonIgnore]
        [JsonIgnore]
        public List<DetectionEvent> Events
        {
            get => RelatedEvents;
            set => RelatedEvents = value ?? new List<DetectionEvent>();
        }

        public static Incident FromDetections(IReadOnlyList<DetectionEvent> events, string title, string? severity = null)
        {
            var sev = severity ?? "medium";
            var relatedRules = events.Select(e => e.RuleId).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var relatedEvents = events.Select(e => e.EventId).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var evidence = events.Count == 0 ? new List<string>() : events.Select(e => $"{e.RuleId}: {e.Description}").ToList();

            return new Incident
            {
                Title = title,
                Severity = sev,
                FirstSeenUtc = DateTime.UtcNow,
                CreatedUtc = DateTime.UtcNow,
                UpdatedUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow,
                RelatedEvents = new List<DetectionEvent>(events),
                PrimaryRuleId = relatedRules.FirstOrDefault(),
                RelatedRuleIds = relatedRules,
                RelatedEventIds = relatedEvents,
                CorrelationReason = "Created from related DetectionEvents",
                EvidenceSummary = evidence.Count == 0 ? null : string.Join("; ", evidence),
                Evidence = evidence
            };
        }
    }
}
