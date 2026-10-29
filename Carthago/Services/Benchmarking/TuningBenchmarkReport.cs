// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkReport.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.Benchmarking
{
    public sealed class TuningBenchmarkSummary
    {
        public int ReplaySampleCount { get; set; }
        public int BenignSampleCount { get; set; }
        public int MaliciousSampleCount { get; set; }
        public int ExpectedMatchCount { get; set; }
        public int MatchedExpectedCount { get; set; }
        public double TruePositivePassRate { get; set; }
        public DetectionQualityMetrics? SampleLevelQuality { get; set; }
        public Dictionary<string, DetectionQualityMetrics> SampleLevelQualityByProfile { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public int BenignFalsePositiveCount { get; set; }
        public int BenignCriticalAlertCount { get; set; }
        public List<string> NoisyRules { get; set; } = new();
        public List<string> RulesWithoutReplayCoverage { get; set; } = new();
        public List<string> RulesWithoutBenignCoverage { get; set; } = new();
        public List<string> RulesRecommendedForShadow { get; set; } = new();
        public List<string> RulesRecommendedForAlert { get; set; } = new();
        public Dictionary<string, int> ConfidenceDistribution { get; set; } = new();
    }

    public sealed class TuningBenchmarkProfileSummary
    {
        public string ProfileName { get; set; } = string.Empty;
        public int AlertCount { get; set; }
        public int ShadowCount { get; set; }
        public int SuppressedCount { get; set; }
        public int BenignAlertCount { get; set; }
        public int BenignCriticalAlertCount { get; set; }
        public int MaliciousExpectedMatchCount { get; set; }
        public int MaliciousAlertMatchCount { get; set; }
        public double TruePositivePassRate { get; set; }
        public List<string> AlertRuleIds { get; set; } = new();
    }

    public sealed class TuningBenchmarkProfileSampleSummary
    {
        public string ProfileName { get; set; } = string.Empty;
        public List<TuningBenchmarkRuleDecision> RuleDecisions { get; set; } = new();
        public List<string> AlertRuleIds { get; set; } = new();
        public List<string> ShadowRuleIds { get; set; } = new();
        public List<string> SuppressedRuleIds { get; set; } = new();
        public int CriticalAlertCount { get; set; }
    }

    public sealed class TuningBenchmarkRuleDecision
    {
        public string RuleId { get; set; } = string.Empty;
        public string Tier { get; set; } = string.Empty;
        public string DefaultMode { get; set; } = string.Empty;
        public string PrecisionMode { get; set; } = string.Empty;
        public string EffectiveMode { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public double? ConfidenceFloor { get; set; }
        public List<string> Reasons { get; set; } = new();
        public List<string> ReasonDetails { get; set; } = new();
        public List<string> RuntimePrecisionReasons { get; set; } = new();
    }

    public sealed class TuningBenchmarkSampleResult
    {
        public string Name { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public ReplaySampleClassification Classification { get; set; }
        public List<string> ExpectedMatches { get; set; } = new();
        public List<string> ExpectedNonMatches { get; set; } = new();
        public List<string> ActualMatches { get; set; } = new();
        public List<string> MissingExpectedMatches { get; set; } = new();
        public List<string> UnexpectedMatches { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public List<TuningBenchmarkExpectedRuleDiagnostic> ExpectedRuleDiagnostics { get; set; } = new();
        public double MaximumConfidence { get; set; }
        public double AverageConfidence { get; set; }
        public Dictionary<string, TuningBenchmarkProfileSampleSummary> Profiles { get; set; } = new();
    }

    public sealed class TuningBenchmarkExpectedRuleDiagnostic
    {
        public string RuleId { get; set; } = string.Empty;
        // Matched, MissingTelemetry, InvalidInputTelemetry, NoMatch, EvaluationFailed or RuleUnavailable.
        public string Outcome { get; set; } = string.Empty;
        public List<string> MissingRequiredTelemetry { get; set; } = new();
        // Metadata-only supplementary DNS input triage. These diagnostic
        // codes do not change rule eligibility, confidence or alert policy.
        public List<string> InputTelemetryIssueCodes { get; set; } = new();
        public int InputRecordsInspected { get; set; }
        public int InputRecordsWithIssues { get; set; }
        public List<string> NoMatchReasons { get; set; } = new();
    }

    /// <summary>
    /// One expected malicious (sample, rule, profile) that did not produce an
    /// alert. A detector match is intentionally not counted as an alert.
    /// </summary>
    public sealed class TuningBenchmarkRecallGap
    {
        public string ProfileName { get; set; } = string.Empty;
        public string SampleName { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string Cause { get; set; } = string.Empty;
        // More than one independent policy/evidence gate can block the alert.
        // Cause is the most actionable gate; BlockingFactors lists every observed gate.
        public List<string> BlockingFactors { get; set; } = new();
        public string DetectionOutcome { get; set; } = string.Empty;
        public string EffectiveMode { get; set; } = string.Empty;
        public double? Confidence { get; set; }
        public double? ConfidenceFloor { get; set; }
        public List<string> Evidence { get; set; } = new();
    }

    /// <summary>
    /// Per-profile accounting of labeled malicious (sample, expected rule)
    /// opportunities. These are simulated replay policy decisions, not live
    /// incident counts or a claim about production sensitivity.
    /// </summary>
    public sealed class TuningBenchmarkDetectionFunnel
    {
        public string ProfileName { get; set; } = string.Empty;
        public int ExpectedMaliciousRules { get; set; }
        public int RecognizedByDetector { get; set; }
        public int DetectorMisses { get; set; }
        public int SimulatedAlerted { get; set; }
        public int PolicyShadowed { get; set; }
        public int PolicyDisabled { get; set; }
        public int MissingPolicyDecisions { get; set; }
        public int EligibleButNotAlerted { get; set; }
        public int AlertDecisionMismatches { get; set; }
        public int BenignRawRuleMatches { get; set; }
        public int BenignSimulatedAlerts { get; set; }
        public int PolicyEligibleRules { get; set; }
        // Nullable ratios distinguish "not measurable" from 0% performance.
        public double? DetectorRecognitionRate { get; set; }
        public double? AlertLevelRecall { get; set; }
        // Conditional emission consistency among recognized, policy-eligible
        // expected matches. NOT detector recall and NOT production precision.
        public double? EligibleAlertEmissionRate { get; set; }
    }

    /// <summary>
    /// Explicit, labeled replay controls for each rule. Malicious expected
    /// matches are positives, and explicit expected nonmatches are negatives.
    /// The absence of a label is never treated as a negative control.
    /// </summary>
    public sealed class TuningBenchmarkRuleEvidenceCoverage
    {
        public string RuleId { get; set; } = string.Empty;
        public int PositiveCases { get; set; }
        public int PositiveRecognized { get; set; }
        public int PositiveMissed { get; set; }
        public int ExplicitNegativeCases { get; set; }
        public int ExplicitNegativePassed { get; set; }
        public int ExplicitNegativeFailed { get; set; }
        // Benign raw matches are not necessarily alert-level false positives.
        public int BenignRawMatches { get; set; }
        public double? PositiveRecognitionRate { get; set; }
        public double? ExplicitNegativePassRate { get; set; }
        public bool HasPairedControls => PositiveCases > 0 && ExplicitNegativeCases > 0;
    }

    public sealed class TuningBenchmarkRuleCoverage
    {
        public string RuleId { get; set; } = string.Empty;
        public int ReplayCoverageCount { get; set; }
        public int BenignCoverageCount { get; set; }
        public int BenignReplayFailures { get; set; }
        public int MaliciousReplayFailures { get; set; }
        public int DefaultProfileBenignAlertCount { get; set; }
        public int DefaultProfileMaliciousAlertCount { get; set; }
        public double AverageConfidence { get; set; }
    }

    public sealed class TuningBenchmarkReport
    {
        public string Name { get; set; } = string.Empty;
        public DateTime GeneratedAtUtc { get; set; }
        public string ReplayDirectory { get; set; } = string.Empty;
        public TuningBenchmarkSummary Summary { get; set; } = new();
        public Dictionary<string, TuningBenchmarkProfileSummary> ProfileResults { get; set; } = new();
        public List<TuningBenchmarkSampleResult> SampleResults { get; set; } = new();
        public List<TuningBenchmarkRecallGap> RecallGaps { get; set; } = new();
        public Dictionary<string, TuningBenchmarkDetectionFunnel> DetectionFunnelByProfile { get; set; }
            = new(StringComparer.OrdinalIgnoreCase);
        public List<TuningBenchmarkRuleCoverage> RuleCoverage { get; set; } = new();
        public List<TuningBenchmarkRuleEvidenceCoverage> RuleEvidenceCoverage { get; set; } = new();
        public List<TuningBenchmarkRuleHardeningEntry> RuleHardeningAudit { get; set; } = new();
    }
}
