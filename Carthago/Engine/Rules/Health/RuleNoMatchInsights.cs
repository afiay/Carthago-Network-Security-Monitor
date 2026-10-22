// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleNoMatchInsights.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Services.RuleTuning;

namespace Carthago.Engine.Rules.Health
{
    public sealed record NoMatchReasonAggregate(
        string RuleId,
        RuleNoMatchReasonCategory Category,
        string Code,
        string Message,
        long Count,
        DateTime? FirstObservedUtc,
        DateTime? LastObservedUtc,
        IReadOnlyDictionary<string, string> LastDetails);

    public sealed record RuleNoMatchStats(
        string RuleId,
        long TotalNoMatches,
        IReadOnlyList<NoMatchReasonAggregate> Reasons)
    {
        public NoMatchReasonAggregate? DominantReason => Reasons
            .OrderByDescending(static reason => reason.Count)
            .ThenBy(static reason => reason.Code, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        public long MissingTelemetryCount => Reasons
            .Where(static reason => reason.Category is RuleNoMatchReasonCategory.MissingTelemetry or RuleNoMatchReasonCategory.MissingRequiredField)
            .Sum(static reason => reason.Count);

        public long SelectorSkippedCount => Reasons
            .Where(static reason => reason.Category == RuleNoMatchReasonCategory.SelectorSkipped)
            .Sum(static reason => reason.Count);

        public long BelowThresholdCount => Reasons
            .Where(static reason => reason.Category == RuleNoMatchReasonCategory.BelowThreshold)
            .Sum(static reason => reason.Count);

        public static RuleNoMatchStats Empty(string ruleId) => new(ruleId, 0, Array.Empty<NoMatchReasonAggregate>());
    }

    internal sealed class NoMatchReasonState
    {
        public string RuleId { get; init; } = string.Empty;
        public RuleNoMatchReasonCategory Category { get; init; }
        public string Code { get; init; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public long Count;
        public DateTime? FirstObservedUtc { get; set; }
        public DateTime? LastObservedUtc { get; set; }
        public IReadOnlyDictionary<string, string> LastDetails { get; set; } = RuleNoMatchReason.EmptyDetails;
    }

    public static class RuleNoMatchReasonStore
    {
        private static readonly ConcurrentDictionary<string, NoMatchReasonState> _states = new(StringComparer.OrdinalIgnoreCase);

        public static void Record(string ruleId, RuleNoMatchReason reason)
        {
            if (reason == null) throw new ArgumentNullException(nameof(reason));
            var id = string.IsNullOrWhiteSpace(ruleId) ? reason.RuleId : ruleId.Trim();
            if (string.IsNullOrWhiteSpace(id)) return;

            var category = reason.Category == RuleNoMatchReasonCategory.Unknown
                ? RuleNoMatchReasonCategory.InsufficientEvidence
                : reason.Category;
            var code = string.IsNullOrWhiteSpace(reason.Code) ? category.ToString().ToUpperInvariant() : reason.Code.Trim();
            var key = BuildKey(id, category, code);
            var state = _states.GetOrAdd(key, _ => new NoMatchReasonState
            {
                RuleId = id,
                Category = category,
                Code = code,
                Message = reason.Message
            });

            lock (state)
            {
                state.Count++;
                state.Message = string.IsNullOrWhiteSpace(reason.Message) ? state.Message : reason.Message;
                state.FirstObservedUtc ??= reason.TimestampUtc;
                state.LastObservedUtc = reason.TimestampUtc;
                state.LastDetails = reason.Details ?? RuleNoMatchReason.EmptyDetails;
            }
        }

        public static void Record(
            string ruleId,
            RuleNoMatchReasonCategory category,
            string code,
            string message,
            DateTime timestampUtc,
            IReadOnlyDictionary<string, string>? details = null)
        {
            Record(ruleId, RuleNoMatchReason.Create(ruleId, category, code, message, timestampUtc, details));
        }

        public static void RecordFromResult(string ruleId, RuleEvaluationResult result, DateTime timestampUtc)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            var id = string.IsNullOrWhiteSpace(ruleId) ? result.RuleId : ruleId.Trim();
            if (string.IsNullOrWhiteSpace(id)) return;

            if (result.NoMatchReasons != null && result.NoMatchReasons.Count > 0)
            {
                foreach (var reason in result.NoMatchReasons)
                    Record(id, reason with { RuleId = id, TimestampUtc = timestampUtc });
                return;
            }

            if (result.Skipped)
            {
                Record(id, RuleNoMatchReasonCategory.Disabled, "RULE_SKIPPED", "Rule was skipped before evaluation.", timestampUtc);
                return;
            }

            if (result.Evaluated && !result.Matched && !result.Failed)
            {
                Record(id, RuleNoMatchReasonCategory.InsufficientEvidence, "INSUFFICIENT_EVIDENCE", "Rule evaluated successfully but did not meet its evidence gates.", timestampUtc);
            }
        }

        public static RuleNoMatchStats Snapshot(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                throw new ArgumentException("Rule ID is required.", nameof(ruleId));

            var id = ruleId.Trim();
            var reasons = _states.Values
                .Where(state => string.Equals(state.RuleId, id, StringComparison.OrdinalIgnoreCase))
                .Select(BuildAggregate)
                .OrderByDescending(static reason => reason.Count)
                .ThenBy(static reason => reason.Code, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return reasons.Length == 0
                ? RuleNoMatchStats.Empty(id)
                : new RuleNoMatchStats(id, reasons.Sum(static reason => reason.Count), reasons);
        }

        public static IReadOnlyList<RuleNoMatchStats> SnapshotAll()
            => _states.Values
                .Select(static state => state.RuleId)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static ruleId => ruleId, StringComparer.OrdinalIgnoreCase)
                .Select(Snapshot)
                .ToArray();

        public static void Reset() => _states.Clear();

        private static NoMatchReasonAggregate BuildAggregate(NoMatchReasonState state)
        {
            lock (state)
            {
                return new NoMatchReasonAggregate(
                    state.RuleId,
                    state.Category,
                    state.Code,
                    state.Message,
                    state.Count,
                    state.FirstObservedUtc,
                    state.LastObservedUtc,
                    state.LastDetails);
            }
        }

        private static string BuildKey(string ruleId, RuleNoMatchReasonCategory category, string code)
            => string.Concat(ruleId.Trim().ToUpperInvariant(), "|", category, "|", code.Trim().ToUpperInvariant());
    }

    public enum RuleTuningRecommendationPriority
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    public sealed record RuleTuningRecommendation(
        string RuleId,
        RuleTuningRecommendationPriority Priority,
        string Code,
        string Title,
        string Rationale,
        string SuggestedAction,
        IReadOnlyList<string> Evidence);

    public sealed record RuleTuningInsight(
        string RuleId,
        double MatchRate,
        double SuppressionRate,
        double FailureRate,
        double MissingTelemetryRate,
        RuleNoMatchStats NoMatchStats,
        IReadOnlyList<RuleTuningRecommendation> Recommendations)
    {
        public RuleTuningRecommendation? HighestPriorityRecommendation => Recommendations
            .OrderByDescending(static recommendation => recommendation.Priority)
            .ThenBy(static recommendation => recommendation.Code, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        public static RuleTuningInsight Empty(string ruleId)
            => new(ruleId, 0.0, 0.0, 0.0, 0.0, RuleNoMatchStats.Empty(ruleId), Array.Empty<RuleTuningRecommendation>());
    }

    public sealed class RuleTuningInsightService
    {
        public RuleTuningInsight Build(
            IDetectionRule rule,
            RuleRuntimeStats runtime,
            RuleNoMatchStats noMatchStats,
            RuleTelemetryCoverageImpact telemetryCoverage,
            RuleMode currentMode,
            IReadOnlyList<RuleCatalogValidationFinding>? validationFindings = null)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));
            runtime ??= RuleRuntimeStatsStore.Snapshot(rule.Descriptor.RuleId);
            noMatchStats ??= RuleNoMatchStats.Empty(rule.Descriptor.RuleId);
            validationFindings ??= Array.Empty<RuleCatalogValidationFinding>();

            var recommendations = new List<RuleTuningRecommendation>();
            var ruleId = rule.Descriptor.RuleId;
            var evaluations = Math.Max(1, runtime.Evaluations);
            var matchRate = runtime.MatchRate;
            var suppressionRate = runtime.Matches <= 0 ? 0.0 : (double)runtime.Suppressed / runtime.Matches;
            var failureRate = runtime.FailureRate;
            var missingTelemetryRate = Math.Max(runtime.MissingTelemetryRate, runtime.Evaluations + runtime.Skipped <= 0 ? 0.0 : (double)noMatchStats.MissingTelemetryCount / Math.Max(1, runtime.Evaluations + runtime.Skipped));

            if (telemetryCoverage.State is RuleTelemetryCoverageState.Unsupported or RuleTelemetryCoverageState.Partial
                || noMatchStats.MissingTelemetryCount > 0
                || missingTelemetryRate >= 0.20)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.High,
                    "ADD_REQUIRED_TELEMETRY",
                    "Add or map missing telemetry before tuning thresholds.",
                    $"The rule is missing required telemetry or has partial telemetry coverage. Missing telemetry count: {noMatchStats.MissingTelemetryCount}.",
                    "Map the required fields from packet, flow, DNS, HTTP, identity, process, cloud, or audit sources before promoting the rule to Alert mode.",
                    telemetryCoverage.MissingRequiredTelemetry.Select(static kind => "missing.telemetry=" + kind).Concat(telemetryCoverage.MissingRequiredFields.Select(static field => "missing.field=" + field)).ToArray()));
            }

            if (failureRate > 0.01 || runtime.Failed > 0)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Critical,
                    "FIX_RULE_FAILURES",
                    "Fix runtime failures before trusting this rule.",
                    $"The rule has {runtime.Failed} recorded failures and a failure rate of {failureRate:P1}.",
                    "Review the latest exception, add null-safe telemetry parsing, and add a regression test for the failing input.",
                    new[] { "failed=" + runtime.Failed, "lastFailedUtc=" + (runtime.LastFailedUtc?.ToString("O") ?? "never") }));
            }

            if (runtime.Evaluations >= 50 && runtime.Matches == 0 && noMatchStats.BelowThresholdCount > 0)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Medium,
                    "REVIEW_THRESHOLD",
                    "Review threshold because the rule repeatedly stays below match gates.",
                    $"The rule evaluated {runtime.Evaluations} times, produced no matches, and reported below-threshold reasons {noMatchStats.BelowThresholdCount} times.",
                    "Check whether the threshold/window is too strict for this environment; keep the rule in Shadow while replay tests confirm any change.",
                    new[] { "evaluations=" + runtime.Evaluations, "belowThreshold=" + noMatchStats.BelowThresholdCount }));
            }

            if (runtime.Matches >= 10 && suppressionRate >= 0.50)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Medium,
                    "CONVERT_REPEAT_SUPPRESSION_TO_POLICY",
                    "Convert repeated suppressions into explicit policy.",
                    $"{suppressionRate:P0} of matches are suppressed.",
                    "Move repeated ad-hoc suppressions into asset roles, approved destinations, maintenance windows, or a documented suppression rule.",
                    new[] { "matches=" + runtime.Matches, "suppressed=" + runtime.Suppressed }));
            }

            var suppressionPolicyStats = RuleSuppressionAuditStore.Snapshot(ruleId);
            if (suppressionPolicyStats.TotalPolicyMatches > 0)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    suppressionPolicyStats.SuppressedByPolicy > 0 ? RuleTuningRecommendationPriority.Medium : RuleTuningRecommendationPriority.Low,
                    "REVIEW_EXPLICIT_SUPPRESSION_POLICY",
                    "Review active suppression policy impact.",
                    $"Explicit suppression policies matched {suppressionPolicyStats.TotalPolicyMatches} times for this rule.",
                    "Keep the policy only if it is documented, scoped to a stable asset/destination/process, and has an expiry or owner where appropriate.",
                    new[]
                    {
                        "policyMatches=" + suppressionPolicyStats.TotalPolicyMatches,
                        "shadowedByPolicy=" + suppressionPolicyStats.ShadowedByPolicy,
                        "suppressedByPolicy=" + suppressionPolicyStats.SuppressedByPolicy,
                        "lastPolicyId=" + (suppressionPolicyStats.LastPolicyId ?? "none")
                    }));
            }

            if (validationFindings.Any(static finding => string.Equals(finding.Code, "BOUNDARY_CONFIG_UNDECLARED", StringComparison.OrdinalIgnoreCase)))
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Medium,
                    "DECLARE_BOUNDARY_POLICY",
                    "Declare environment boundary requirements.",
                    "The rule appears to use internal/external logic but does not declare the required environment configuration.",
                    "Declare required internal CIDRs, DMZ ranges, VPN pools, management ranges, and approved external destinations in the rule precision profile.",
                    new[] { "validation=BOUNDARY_CONFIG_UNDECLARED" }));
            }

            if (currentMode == RuleMode.Alert && rule.Intelligence?.PrecisionProfile?.DefaultMode == RuleRuntimeMode.Shadow && runtime.Matches == 0 && runtime.Evaluations < 20)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Low,
                    "KEEP_IN_SHADOW_UNTIL_OBSERVED",
                    "Keep low-observation candidate rule in Shadow.",
                    "The rule has little runtime evidence in this environment.",
                    "Collect replay samples and live observations before promoting to Alert mode.",
                    new[] { "evaluations=" + runtime.Evaluations, "defaultMode=" + RuleRuntimeMode.Shadow }));
            }

            if (recommendations.Count == 0 && runtime.Evaluations >= 20 && runtime.Failed == 0 && missingTelemetryRate < 0.05)
            {
                recommendations.Add(new RuleTuningRecommendation(
                    ruleId,
                    RuleTuningRecommendationPriority.Info,
                    "NO_TUNING_ACTION",
                    "No immediate tuning action detected.",
                    "Runtime health, telemetry coverage, and suppression behavior do not currently indicate a tuning problem.",
                    "Continue collecting runtime statistics and replay coverage.",
                    new[] { "evaluations=" + runtime.Evaluations, "matches=" + runtime.Matches }));
            }

            return new RuleTuningInsight(
                ruleId,
                matchRate,
                suppressionRate,
                failureRate,
                missingTelemetryRate,
                noMatchStats,
                recommendations);
        }
    }
}
