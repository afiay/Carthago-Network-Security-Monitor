// SPDX-License-Identifier: MIT
// File: Services/ViewModels/V6ViewModels.cs
using System.Collections.Generic;
using Carthago.Analytics.Models;
using Carthago.Services.Diagnostics;
using Carthago.Services.EntityGraph;
using Carthago.Services.Hunting;
using Carthago.Services.Response;
using Carthago.Services.Sensors;
using Carthago.Services.Timeline;
using Carthago.Services.Triage;

namespace Carthago.Services.ViewModels
{
    public sealed class EntityRiskViewModel { public List<EntityRiskScore> Items { get; set; } = new(); }
    public sealed class IncidentStoryViewModel { public Incident Incident { get; set; } = new(); public List<string> RelatedRuleIds { get; set; } = new(); }
    public sealed class AttackTimelineViewModel { public TimelineEvidenceBundle Bundle { get; set; } = new(); }
    public sealed class RuleHealthViewModel { public List<RuleHealthDiagnostic> Rules { get; set; } = new(); }
    public sealed class TriageCaseViewModel { public TriageCase Case { get; set; } = new(); }
    public sealed class ResponseRecommendationViewModel { public List<ResponseAction> Recommendations { get; set; } = new(); }
    public sealed class SensorHealthViewModel { public List<SensorHealth> Sensors { get; set; } = new(); }
    public sealed class HuntResultViewModel { public HuntQueryResult Result { get; set; } = new(); }
    public sealed class BenchmarkScorecardViewModel
    {
        public bool Passed { get; set; }
        public int ReplaySampleCount { get; set; }
        public int CoverageGapCount { get; set; }
        public string Summary { get; set; } = string.Empty;
    }
}
