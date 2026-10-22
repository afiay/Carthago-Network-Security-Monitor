// SPDX-License-Identifier: MIT
// File: Services/Diagnostics/RuleHealthDiagnosticsService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Carthago.Services.Feedback;
using Carthago.Services.RuleTuning;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Diagnostics
{
    public sealed class RuleHealthDiagnosticsService
    {
        private readonly DetectionJournalReader _journalReader;
        private readonly DetectionFeedbackStore _feedbackStore;
        private readonly TuningBenchmarkReportStore _benchmarkStore;
        private readonly RuleReplayReportStore _replayReportStore;
        private readonly string _benchmarkOutputDirectory;

        public RuleHealthDiagnosticsService(
            DetectionJournalOptions? journalOptions = null,
            DetectionFeedbackStore? feedbackStore = null,
            TuningBenchmarkReportStore? benchmarkStore = null,
            RuleReplayReportStore? replayReportStore = null,
            string? benchmarkOutputDirectory = null)
        {
            _journalReader = new DetectionJournalReader(journalOptions ?? new DetectionJournalOptions());
            _feedbackStore = feedbackStore ?? DetectionFeedbackStore.Current;
            _benchmarkStore = benchmarkStore ?? new TuningBenchmarkReportStore();
            _replayReportStore = replayReportStore ?? new RuleReplayReportStore();
            _benchmarkOutputDirectory = string.IsNullOrWhiteSpace(benchmarkOutputDirectory) ? "build-verify" : benchmarkOutputDirectory!;
        }

        public IReadOnlyList<RuleHealthDiagnostic> Snapshot()
            => SnapshotAsync().GetAwaiter().GetResult();

        public async Task<IReadOnlyList<RuleHealthDiagnostic>> SnapshotAsync(DateTime? nowUtc = null, CancellationToken cancellationToken = default)
        {
            var now = nowUtc ?? DateTime.UtcNow;
            var rules = RuleRegistry.CreateDefaultRules();
            var recentEvents = await ReadRecentEventsAsync(now, cancellationToken).ConfigureAwait(false);
            var feedback = await ReadFeedbackAsync(cancellationToken).ConfigureAwait(false);
            var benchmark = await _benchmarkStore.LoadAsync(_benchmarkOutputDirectory, cancellationToken).ConfigureAwait(false);
            var replayReport = await _replayReportStore.LoadAsync(_benchmarkOutputDirectory, cancellationToken).ConfigureAwait(false);
            var replayCoverageByRule = new RuleReplayCoverageService().Build(replayReport, rules.Select(static rule => rule.Descriptor));
            var structuredValidation = new RuleCatalogValidator().Validate(rules);
            var qualityScorer = new RuleQualityScorer();
            var tuningInsightService = new RuleTuningInsightService();
            var telemetryCoverageService = new RuleTelemetryCoverageService(() => rules);
            var validationByRuleId = structuredValidation.Findings
                .Where(static finding => !string.IsNullOrWhiteSpace(finding.RuleId))
                .GroupBy(static finding => finding.RuleId!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

            return rules.Select(rule =>
            {
                var id = rule.Descriptor.RuleId;
                var runtime = RuleRuntimeTelemetryStore.Snapshot(id);
                var precisionRuntime = RuleRuntimeStatsStore.Snapshot(id);
                var quality = qualityScorer.Score(rule, structuredValidation, precisionRuntime);
                var validationFindings = validationByRuleId.TryGetValue(id, out var ruleFindings) ? ruleFindings : Array.Empty<RuleCatalogValidationFinding>();
                var journalStats = BuildJournalStats(id, recentEvents);
                var feedbackStats = feedback.TryGetValue(id, out var entry) ? entry : FeedbackStats.Empty;
                var coverage = benchmark?.RuleCoverage.FirstOrDefault(item => string.Equals(item.RuleId, id, StringComparison.OrdinalIgnoreCase));
                var replayCoverage = replayCoverageByRule.TryGetValue(id, out var replayCoverageSnapshot) ? replayCoverageSnapshot : RuleReplayCoverageSnapshot.Empty(id);
                var currentDecision = RuleTuningCatalog.Resolve(RuleTuningCatalog.DefaultProfileName, rule.Descriptor);
                var feedbackRecommendation = new RuleFeedbackAdvisor(_feedbackStore).Recommend(
                    currentDecision,
                    new RuleFeedbackSummary(id, feedbackStats.FalsePositiveCount, feedbackStats.TruePositiveCount, feedbackStats.ExpectedActivityCount, feedbackStats.SuppressSimilarCount));

                var recommendedMode = ComputeRecommendedMode(feedbackRecommendation, coverage, journalStats, runtime);
                var recommendedThreshold = feedbackRecommendation.RecommendedThreshold;
                var healthScore = ComputeHealthScore(journalStats, feedbackStats, coverage, runtime, recommendedMode);
                var noMatchStats = RuleNoMatchReasonStore.Snapshot(id);
                var telemetryCoverage = telemetryCoverageService.GetImpact(rule);
                var tuningInsight = tuningInsightService.Build(rule, precisionRuntime, noMatchStats, telemetryCoverage, RuleEngine.GetRuleMode(id, rule.Descriptor.EnabledByDefault), validationFindings);
                var suppressionPolicyStats = RuleSuppressionAuditStore.Snapshot(id);
                var dominantNoMatch = noMatchStats.DominantReason;
                var topRecommendation = tuningInsight.HighestPriorityRecommendation;

                return new RuleHealthDiagnostic
                {
                    RuleId = id,
                    Name = rule.Descriptor.Name,
                    Category = rule.Descriptor.Category,
                    Mode = RuleEngine.GetRuleMode(id, rule.Descriptor.EnabledByDefault),
                    Maturity = rule.Intelligence.Maturity,
                    SignalKind = rule.Intelligence.SignalKind,
                    Revision = rule.Intelligence.Revision,
                    LastEvaluatedUtc = runtime.LastEvaluatedUtc,
                    LastMatchedUtc = journalStats.LastMatchedUtc ?? runtime.LastMatchedUtc,
                    LastPersistedUtc = journalStats.LastPersistedUtc ?? runtime.LastPersistedUtc,
                    EvaluatedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleEvaluatedTotal),
                    MatchedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleMatchedTotal),
                    SuppressedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleSuppressedTotal),
                    ShadowedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleShadowedTotal),
                    PersistedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RulePersistedTotal),
                    FailedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleFailedTotal),
                    SinkFailedCount = RuleEngineMetrics.Get(id, RuleMetricNames.RuleSinkFailedTotal),
                    LastFailure = runtime.LastFailure,
                    MissingTelemetryWarnings = RuleEngine.LastEvaluationTrace?.TelemetryWarnings.Where(w => w.Contains(id, StringComparison.OrdinalIgnoreCase)).ToList() ?? new List<string>(),
                    FalsePositiveCount = feedbackStats.FalsePositiveCount,
                    TruePositiveCount = feedbackStats.TruePositiveCount,
                    ExpectedActivityCount = feedbackStats.ExpectedActivityCount,
                    AlertCount24h = journalStats.AlertCount24h,
                    ShadowCount24h = journalStats.ShadowCount24h,
                    SuppressedCount24h = journalStats.SuppressedCount24h,
                    BenignReplayFailures = coverage?.BenignReplayFailures ?? 0,
                    MaliciousReplayFailures = coverage?.MaliciousReplayFailures ?? 0,
                    ReplayCoverageStatus = replayCoverage.Status.ToString(),
                    ReplaySampleCount = replayCoverage.SampleCount,
                    ReplayBenignSampleCount = replayCoverage.BenignSampleCount,
                    ReplayMaliciousSampleCount = replayCoverage.MaliciousSampleCount,
                    ReplayExpectedMatchCount = replayCoverage.ExpectedMatchCount,
                    ReplayActualMatchCount = replayCoverage.ActualMatchCount,
                    ReplayMissingExpectedCount = replayCoverage.MissingExpectedCount,
                    ReplayUnexpectedMatchCount = replayCoverage.UnexpectedMatchCount,
                    ReplayFailedSampleCount = replayCoverage.FailedSampleCount,
                    ReplayAverageConfidence = replayCoverage.AverageConfidence,
                    ReplayMaximumConfidence = replayCoverage.MaximumConfidence,
                    AverageConfidence = journalStats.AverageConfidence > 0 ? journalStats.AverageConfidence : runtime.AverageConfidence,
                    LastTuningDecision = runtime.LastTuningDecisionSummary ?? journalStats.LastTuningDecision,
                    RecommendedMode = recommendedMode,
                    RecommendedThreshold = recommendedThreshold,
                    MissingTelemetryRate = runtime.MissingTelemetryRate,
                    PerformanceCostEstimate = runtime.EvaluatedCount,
                    HealthScore = healthScore,
                    QualityScore = quality.TotalScore,
                    QualityGrade = quality.Grade,
                    ValidationErrorCount = validationFindings.Count(static finding => finding.IsError),
                    ValidationWarningCount = validationFindings.Count(static finding => finding.Severity == RuleCatalogValidationSeverity.Warning),
                    RuntimeAverageDurationMicroseconds = precisionRuntime.AverageDurationMicroseconds,
                    RuntimeMaxDurationMicroseconds = precisionRuntime.MaxDurationMicroseconds,
                    NoMatchCount = noMatchStats.TotalNoMatches,
                    DominantNoMatchReasonCode = dominantNoMatch?.Code,
                    DominantNoMatchReasonCategory = dominantNoMatch?.Category.ToString(),
                    DominantNoMatchReasonMessage = dominantNoMatch?.Message,
                    DominantNoMatchReasonCount = dominantNoMatch?.Count ?? 0,
                    TuningRecommendationCount = tuningInsight.Recommendations.Count,
                    HighestTuningRecommendationPriority = topRecommendation?.Priority,
                    HighestTuningRecommendationCode = topRecommendation?.Code,
                    HighestTuningRecommendationTitle = topRecommendation?.Title,
                    SuppressionPolicyMatchCount = suppressionPolicyStats.TotalPolicyMatches,
                    ShadowedBySuppressionPolicyCount = suppressionPolicyStats.ShadowedByPolicy,
                    SuppressedBySuppressionPolicyCount = suppressionPolicyStats.SuppressedByPolicy,
                    ActiveSuppressionPolicyCount = suppressionPolicyStats.ActivePolicyCount,
                    LastSuppressionPolicyMatchedUtc = suppressionPolicyStats.LastMatchedUtc,
                    LastSuppressionPolicyId = suppressionPolicyStats.LastPolicyId,
                    LastSuppressionPolicyReason = suppressionPolicyStats.LastReason
                };
            }).OrderBy(x => x.RuleId, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private async Task<List<DetectionEvent>> ReadRecentEventsAsync(DateTime nowUtc, CancellationToken cancellationToken)
        {
            var results = new List<DetectionEvent>();
            foreach (var day in new[] { nowUtc.Date, nowUtc.Date.AddDays(-1) })
            {
                await foreach (var evt in _journalReader.ReadDayAsync(day, cancellationToken).ConfigureAwait(false))
                {
                    if (evt.TimestampUtc >= nowUtc.AddHours(-24))
                        results.Add(evt);
                }
            }

            return results;
        }

        private async Task<Dictionary<string, FeedbackStats>> ReadFeedbackAsync(CancellationToken cancellationToken)
        {
            var results = new Dictionary<string, FeedbackStats>(StringComparer.OrdinalIgnoreCase);
            await foreach (var item in _feedbackStore.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (string.IsNullOrWhiteSpace(item.RuleId))
                    continue;

                var stats = results.TryGetValue(item.RuleId, out var current) ? current : FeedbackStats.Empty;
                stats = item.Verdict switch
                {
                    DetectionFeedbackVerdict.FalsePositive => stats with { FalsePositiveCount = stats.FalsePositiveCount + 1 },
                    DetectionFeedbackVerdict.TruePositive => stats with { TruePositiveCount = stats.TruePositiveCount + 1 },
                    DetectionFeedbackVerdict.ExpectedActivity => stats with { ExpectedActivityCount = stats.ExpectedActivityCount + 1 },
                    DetectionFeedbackVerdict.SuppressSimilar => stats with { SuppressSimilarCount = stats.SuppressSimilarCount + 1 },
                    _ => stats
                };
                results[item.RuleId] = stats;
            }

            return results;
        }

        private static JournalStats BuildJournalStats(string ruleId, IReadOnlyList<DetectionEvent> events)
        {
            var relevant = events
                .Where(evt => string.Equals(evt.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(evt => evt.TimestampUtc)
                .ToArray();
            if (relevant.Length == 0)
                return JournalStats.Empty;

            var alertCount = relevant.Count(evt => evt.SuppressionStatus == DetectionSuppressionStatus.None);
            var shadowCount = relevant.Count(evt => evt.SuppressionStatus == DetectionSuppressionStatus.Shadowed);
            var suppressedCount = relevant.Count(evt => evt.SuppressionStatus == DetectionSuppressionStatus.Suppressed);
            var avgConfidence = relevant.Average(evt => evt.ConfidenceScore);
            var latest = relevant[0];
            var latestTuning = ExtractLatestTuningDecision(latest);
            return new JournalStats(
                AlertCount24h: alertCount,
                ShadowCount24h: shadowCount,
                SuppressedCount24h: suppressedCount,
                AverageConfidence: avgConfidence,
                LastMatchedUtc: latest.TimestampUtc,
                LastPersistedUtc: latest.PersistedAtUtc,
                LastTuningDecision: latestTuning);
        }

        private static string? ExtractLatestTuningDecision(DetectionEvent evt)
        {
            var items = evt.StructuredEvidence?.Items;
            if (items == null || items.Count == 0)
                return null;

            var mode = items.LastOrDefault(item => string.Equals(item.Key, "tuning.effectiveMode", StringComparison.OrdinalIgnoreCase))?.Value;
            var tier = items.LastOrDefault(item => string.Equals(item.Key, "tuning.tier", StringComparison.OrdinalIgnoreCase))?.Value;
            if (string.IsNullOrWhiteSpace(mode) && string.IsNullOrWhiteSpace(tier))
                return null;

            return string.IsNullOrWhiteSpace(tier) ? mode : $"{tier}:{mode}";
        }

        private static RuleMode ComputeRecommendedMode(
            RuleFeedbackRecommendation feedbackRecommendation,
            TuningBenchmarkRuleCoverage? coverage,
            JournalStats journalStats,
            RuleRuntimeTelemetrySnapshot runtime)
        {
            var mode = feedbackRecommendation.RecommendedMode;

            if ((coverage?.BenignReplayFailures ?? 0) > 0
                || journalStats.ShadowCount24h > journalStats.AlertCount24h
                || journalStats.SuppressedCount24h > 0)
            {
                return mode == RuleMode.Disabled ? RuleMode.Disabled : RuleMode.Shadow;
            }

            if ((coverage?.MaliciousReplayFailures ?? 0) == 0
                && journalStats.AverageConfidence >= 0.80
                && runtime.MatchedCount > 0)
            {
                return RuleMode.Alert;
            }

            return mode;
        }

        private static int ComputeHealthScore(
            JournalStats journalStats,
            FeedbackStats feedbackStats,
            TuningBenchmarkRuleCoverage? coverage,
            RuleRuntimeTelemetrySnapshot runtime,
            RuleMode recommendedMode)
        {
            var score = 55.0;
            score += Math.Min(16, feedbackStats.TruePositiveCount * 4);
            score -= Math.Min(20, feedbackStats.FalsePositiveCount * 5);
            score -= Math.Min(8, feedbackStats.ExpectedActivityCount * 2);

            if (coverage != null)
            {
                if (coverage.ReplayCoverageCount > 0)
                    score += 8;
                if (coverage.BenignCoverageCount > 0)
                    score += 4;
                score -= Math.Min(18, coverage.BenignReplayFailures * 6);
                score -= Math.Min(15, coverage.MaliciousReplayFailures * 5);
            }

            score -= Math.Min(18, runtime.MissingTelemetryRate * 40);

            if (journalStats.AverageConfidence >= 0.80)
                score += 8;
            else if (journalStats.AverageConfidence > 0 && journalStats.AverageConfidence < 0.50)
                score -= 6;

            if (recommendedMode == RuleMode.Shadow)
                score -= 8;
            if (recommendedMode == RuleMode.Disabled)
                score -= 12;

            if (runtime.EvaluatedCount > 0 && runtime.MatchedCount == 0)
                score -= 4;
            if (runtime.EvaluatedCount > 0 && runtime.MatchedCount > 0 && runtime.EvaluatedCount > runtime.MatchedCount * 25)
                score -= 5;

            return (int)Math.Clamp(Math.Round(score), 0, 100);
        }

        private sealed record JournalStats(
            int AlertCount24h,
            int ShadowCount24h,
            int SuppressedCount24h,
            double AverageConfidence,
            DateTime? LastMatchedUtc,
            DateTime? LastPersistedUtc,
            string? LastTuningDecision)
        {
            public static JournalStats Empty { get; } = new(0, 0, 0, 0.0, null, null, null);
        }

        private sealed record FeedbackStats(
            int FalsePositiveCount,
            int TruePositiveCount,
            int ExpectedActivityCount,
            int SuppressSimilarCount)
        {
            public static FeedbackStats Empty { get; } = new(0, 0, 0, 0);
        }
    }
}
