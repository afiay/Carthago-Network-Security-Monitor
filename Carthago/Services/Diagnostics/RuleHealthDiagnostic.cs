// SPDX-License-Identifier: MIT
// File: Services/Diagnostics/RuleHealthDiagnostic.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;

namespace Carthago.Services.Diagnostics
{
    public sealed class RuleHealthDiagnostic
    {
        public string RuleId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public RuleMode Mode { get; set; }
        public RuleMaturity Maturity { get; set; }
        public RuleSignalKind SignalKind { get; set; }
        public int Revision { get; set; }
        public DateTime? LastEvaluatedUtc { get; set; }
        public DateTime? LastMatchedUtc { get; set; }
        public DateTime? LastPersistedUtc { get; set; }
        public long EvaluatedCount { get; set; }
        public long MatchedCount { get; set; }
        public long SuppressedCount { get; set; }
        public long ShadowedCount { get; set; }
        public long PersistedCount { get; set; }
        public long FailedCount { get; set; }
        public long SinkFailedCount { get; set; }
        public string? LastFailure { get; set; }
        public List<string> MissingTelemetryWarnings { get; set; } = new();
        public long FalsePositiveCount { get; set; }
        public long TruePositiveCount { get; set; }
        public long ExpectedActivityCount { get; set; }
        public long AlertCount24h { get; set; }
        public long ShadowCount24h { get; set; }
        public long SuppressedCount24h { get; set; }
        public long BenignReplayFailures { get; set; }
        public long MaliciousReplayFailures { get; set; }
        public string ReplayCoverageStatus { get; set; } = "NoCoverage";
        public int ReplaySampleCount { get; set; }
        public int ReplayBenignSampleCount { get; set; }
        public int ReplayMaliciousSampleCount { get; set; }
        public int ReplayExpectedMatchCount { get; set; }
        public int ReplayActualMatchCount { get; set; }
        public int ReplayMissingExpectedCount { get; set; }
        public int ReplayUnexpectedMatchCount { get; set; }
        public int ReplayFailedSampleCount { get; set; }
        public double ReplayAverageConfidence { get; set; }
        public double ReplayMaximumConfidence { get; set; }
        public double AverageConfidence { get; set; }
        public double ConfidenceAverage { get => AverageConfidence; set => AverageConfidence = value; }
        public string? LastTuningDecision { get; set; }
        public RuleMode RecommendedMode { get; set; }
        public int? RecommendedThreshold { get; set; }
        public double MissingTelemetryRate { get; set; }
        public double PerformanceCostEstimate { get; set; }
        public int HealthScore { get; set; }
        public int QualityScore { get; set; }
        public RuleQualityGrade QualityGrade { get; set; }
        public int ValidationErrorCount { get; set; }
        public int ValidationWarningCount { get; set; }
        public double RuntimeAverageDurationMicroseconds { get; set; }
        public double RuntimeMaxDurationMicroseconds { get; set; }
        public long NoMatchCount { get; set; }
        public string? DominantNoMatchReasonCode { get; set; }
        public string? DominantNoMatchReasonCategory { get; set; }
        public string? DominantNoMatchReasonMessage { get; set; }
        public long DominantNoMatchReasonCount { get; set; }
        public int TuningRecommendationCount { get; set; }
        public RuleTuningRecommendationPriority? HighestTuningRecommendationPriority { get; set; }
        public string? HighestTuningRecommendationCode { get; set; }
        public string? HighestTuningRecommendationTitle { get; set; }
        public long SuppressionPolicyMatchCount { get; set; }
        public long ShadowedBySuppressionPolicyCount { get; set; }
        public long SuppressedBySuppressionPolicyCount { get; set; }
        public int ActiveSuppressionPolicyCount { get; set; }
        public DateTime? LastSuppressionPolicyMatchedUtc { get; set; }
        public string? LastSuppressionPolicyId { get; set; }
        public string? LastSuppressionPolicyReason { get; set; }
    }
}
