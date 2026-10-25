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
        public List<string> AlertRuleIds { get; set; } = new();
        public List<string> ShadowRuleIds { get; set; } = new();
        public List<string> SuppressedRuleIds { get; set; } = new();
        public int CriticalAlertCount { get; set; }
    }

    public sealed class TuningBenchmarkSampleResult
    {
        public string Name { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public ReplaySampleClassification Classification { get; set; }
        public List<string> ExpectedMatches { get; set; } = new();
        public List<string> ActualMatches { get; set; } = new();
        public List<string> MissingExpectedMatches { get; set; } = new();
        public List<string> UnexpectedMatches { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public double MaximumConfidence { get; set; }
        public double AverageConfidence { get; set; }
        public Dictionary<string, TuningBenchmarkProfileSampleSummary> Profiles { get; set; } = new();
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
        public List<TuningBenchmarkRuleCoverage> RuleCoverage { get; set; } = new();
    }
}
