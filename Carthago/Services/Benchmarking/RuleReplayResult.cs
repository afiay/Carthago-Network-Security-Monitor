// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/RuleReplayResult.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Services.Benchmarking
{
    public sealed class RuleReplayRunOptions
    {
        public bool ResetRuntimeStateBeforeSample { get; set; } = true;
        public bool UseRuleEngine { get; set; } = true;
        public bool TreatUnexpectedMatchesAsFailure { get; set; } = true;
        public bool TreatBenignEmissionsAsFailure { get; set; } = true;
        public bool RequireExpectedMatchesToEmit { get; set; }
        public int MaximumUnexpectedMatchCount { get; set; }
        public Sensitivity Sensitivity { get; set; } = Sensitivity.Balanced;
    }

    public sealed class RuleReplaySampleAssertion
    {
        public string RuleId { get; set; } = string.Empty;
        public bool MustMatch { get; set; }
        public bool MustEmit { get; set; }
        public bool MustNotMatch { get; set; }
        public bool MustSuppress { get; set; }
        public bool MustShadow { get; set; }
        public double MinimumConfidence { get; set; }
        public SeverityLevel? MinimumSeverity { get; set; }
        public List<string> RequiredEvidenceKeys { get; set; } = new();
        public List<string> RequiredNoMatchReasonCodes { get; set; } = new();
    }

    public sealed class RuleReplayRuleObservation
    {
        public string RuleId { get; set; } = string.Empty;
        public int MatchedCount { get; set; }
        public int EmittedCount { get; set; }
        public int SuppressedCount { get; set; }
        public int ShadowedCount { get; set; }
        public int FailedCount { get; set; }
        public int NoMatchReasonCount { get; set; }
        public double MaximumConfidence { get; set; }
        public double AverageConfidence { get; set; }
        public SeverityLevel? MaximumSeverity { get; set; }
        public List<string> EvidenceKeys { get; set; } = new();
        public List<string> NoMatchReasonCodes { get; set; } = new();
    }

    public sealed class RuleReplaySampleResult
    {
        public string Name { get; set; } = string.Empty;
        public string? FilePath { get; set; }
        public ReplaySampleClassification Classification { get; set; }
        public int RecordCount { get; set; }
        public int TraceCount { get; set; }
        public int DetectionCount { get; set; }
        public TimeSpan Duration { get; set; }
        public List<DetectionEvent> Detections { get; set; } = new();
        public List<string> ExpectedMatchRuleIds { get; set; } = new();
        public List<string> ExpectedNonMatchRuleIds { get; set; } = new();
        public List<string> MatchedRuleIds { get; set; } = new();
        public List<string> EmittedRuleIds { get; set; } = new();
        public List<string> SuppressedRuleIds { get; set; } = new();
        public List<string> ShadowedRuleIds { get; set; } = new();
        public List<string> FailedRuleIds { get; set; } = new();
        public List<string> UnexpectedRuleIds { get; set; } = new();
        public List<string> MissingExpectedRuleIds { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public List<RuleReplayRuleObservation> RuleObservations { get; set; } = new();
        public Dictionary<string, List<string>> NoMatchReasonCodesByRuleId { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        public bool Passed => Errors.Count == 0;
    }

    public sealed class RuleReplayDirectorySummary
    {
        public int SampleCount { get; set; }
        public int PassedSampleCount { get; set; }
        public int FailedSampleCount { get; set; }
        public int BenignSampleCount { get; set; }
        public int MaliciousSampleCount { get; set; }
        public int TotalDetections { get; set; }
        public int TotalUnexpectedMatches { get; set; }
        public int TotalMissingExpectedMatches { get; set; }
        public double PassRate => SampleCount <= 0 ? 1.0 : (double)PassedSampleCount / SampleCount;
        public List<string> NoisyRules { get; set; } = new();
        public List<string> RulesWithNoReplayCoverage { get; set; } = new();
    }

    public sealed class RuleReplayDirectoryResult
    {
        public string ReplayDirectory { get; set; } = string.Empty;
        public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
        public RuleReplayDirectorySummary Summary { get; set; } = new();
        public List<RuleReplaySampleResult> Samples { get; set; } = new();
        public bool Passed => Samples.All(static sample => sample.Passed);
    }
}
