// SPDX-License-Identifier: MIT
// File: Services/Triage/TriageModels.cs
using System;
using System.Collections.Generic;
using Carthago.Analytics.Models;

namespace Carthago.Services.Triage
{
    public sealed class TriageReason
    {
        public string Message { get; set; } = string.Empty;
        public string? EventId { get; set; }
        public string? EntityId { get; set; }
        public string? RuleId { get; set; }
    }

    public sealed class TriageChecklist
    {
        public List<string> InvestigationSteps { get; set; } = new();
        public List<string> MissingEvidence { get; set; } = new();
        public List<string> FalsePositiveHypotheses { get; set; } = new();
        public List<string> TuningSuggestions { get; set; } = new();
    }

    public sealed class TriageRecommendation
    {
        public string RecommendationId { get; set; } = Guid.NewGuid().ToString("N");
        public string Text { get; set; } = string.Empty;
        public bool RequiresApproval { get; set; }
        public string? SourceEventId { get; set; }
        public string? SourceIncidentId { get; set; }
    }

    public sealed class TriageDecision
    {
        public TriageSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public AttackStoryType LikelyStoryType { get; set; }
        public List<TriageReason> Reasons { get; set; } = new();
        public List<TriageRecommendation> SafeActions { get; set; } = new();
        public List<TriageRecommendation> ApprovalRequiredActions { get; set; } = new();
    }

    public sealed class TriageCase
    {
        public string CaseId { get; set; } = Guid.NewGuid().ToString("N");
        public string? IncidentId { get; set; }
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public TriageDecision Decision { get; set; } = new();
        public TriageChecklist Checklist { get; set; } = new();
        public List<string> AffectedEntityIds { get; set; } = new();
        public List<string> SupportingEventIds { get; set; } = new();
        public List<string> RelatedReplaySamples { get; set; } = new();
    }

    public sealed class TriageOptions
    {
        public bool EnableAiSummary { get; set; }
        public bool RequireJournaledEvents { get; set; } = true;
    }
}
