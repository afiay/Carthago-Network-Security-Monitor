// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkRecallGapAnalyzer.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Classifies missed expected malicious alerts without treating a raw match,
    /// a Shadow decision, or a suppressed event as a true-positive alert.
    /// A cause describes the observable gate; it is not an authorization to
    /// lower confidence floors or promote rules to Alert mode.
    /// </summary>
    public static class TuningBenchmarkRecallGapAnalyzer
    {
        public static List<TuningBenchmarkRecallGap> Analyze(TuningBenchmarkReport report)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));

            var gaps = new List<TuningBenchmarkRecallGap>();
            foreach (var sample in report.SampleResults.Where(
                static sample => sample.Classification == ReplaySampleClassification.Malicious))
            {
                foreach (var profile in sample.Profiles.OrderBy(
                    static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
                {
                    foreach (var ruleId in sample.ExpectedMatches.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if (profile.Value.AlertRuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase))
                            continue;

                        var diagnostic = sample.ExpectedRuleDiagnostics.FirstOrDefault(item =>
                            string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
                        var decision = profile.Value.RuleDecisions.FirstOrDefault(item =>
                            string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
                        // Prefer the recorded evaluation outcome, but preserve the actual
                        // match set when a legacy report has no diagnostics.
                        var matched = diagnostic != null
                            ? string.Equals(diagnostic.Outcome, "Matched", StringComparison.OrdinalIgnoreCase)
                            : sample.ActualMatches.Contains(ruleId, StringComparer.OrdinalIgnoreCase);
                        var outcome = diagnostic?.Outcome ?? (matched ? "Matched" : "NoMatch");

                        var evidence = new List<string>();
                        if (!matched)
                        {
                            if (diagnostic != null)
                            {
                                evidence.AddRange(diagnostic.MissingRequiredTelemetry
                                    .Select(static missing => "Missing telemetry: " + missing));
                                evidence.AddRange(diagnostic.NoMatchReasons);
                            }
                        }
                        else if (decision != null)
                        {
                            // Keep actionable precision diagnostics ahead of
                            // generic tuning-tier descriptions in bounded reports.
                            evidence.AddRange(decision.RuntimePrecisionReasons);
                            evidence.AddRange(decision.ReasonDetails);
                            if (evidence.Count == 0)
                                evidence.AddRange(decision.Reasons);
                        }

                        var blockingFactors = GetBlockingFactors(matched, outcome, decision);
                        gaps.Add(new TuningBenchmarkRecallGap
                        {
                            ProfileName = profile.Key,
                            SampleName = sample.Name,
                            RuleId = ruleId,
                            Cause = blockingFactors[0],
                            BlockingFactors = blockingFactors,
                            DetectionOutcome = outcome,
                            EffectiveMode = decision?.EffectiveMode ?? "NoDecision",
                            Confidence = decision?.Confidence,
                            ConfidenceFloor = decision?.ConfidenceFloor,
                            Evidence = evidence.Where(static item => !string.IsNullOrWhiteSpace(item))
                                .Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList()
                        });
                    }
                }
            }

            return gaps.OrderBy(static gap => gap.ProfileName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static gap => gap.Cause, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static gap => gap.RuleId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static gap => gap.SampleName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static List<string> GetBlockingFactors(
            bool matched, string outcome, TuningBenchmarkRuleDecision? decision)
        {
            if (!matched)
            {
                return new List<string>
                {
                    outcome switch
                    {
                        "MissingTelemetry" => "MissingTelemetry",
                        "EvaluationFailed" => "DetectorFailure",
                        "RuleUnavailable" => "RuleUnavailable",
                        _ => "NoMatch"
                    }
                };
            }

            if (decision == null)
                return new List<string> { "NoPolicyDecision" };

            var factors = new List<string>();
            if (HasReason(decision.Reasons, "ApprovedAssetMatched"))
                factors.Add("ApprovedAsset");
            if (HasReason(decision.Reasons, "ConfidenceFloorApplied"))
                factors.Add("ConfidenceFloor");
            if (HasReason(decision.RuntimePrecisionReasons, "below precision floor"))
                factors.Add("PrecisionConfidenceFloor");
            if (HasReason(decision.RuntimePrecisionReasons, "environment-scoped rule lacks"))
                factors.Add("EnvironmentApprovalRequired");
            if (HasReason(decision.Reasons, "MissingEnvironmentConfiguration"))
                factors.Add("EnvironmentConfigurationRequired");
            if (HasReason(decision.RuntimePrecisionReasons, "baseline not ready")
                || HasReason(decision.RuntimePrecisionReasons, "baseline readiness required"))
                factors.Add("BaselineNotReady");
            if (string.Equals(decision.EffectiveMode, "Disabled", StringComparison.OrdinalIgnoreCase))
                factors.Add("Disabled");
            if (!string.Equals(decision.DefaultMode, "Alert", StringComparison.OrdinalIgnoreCase))
                factors.Add("ProfileShadow");
            if (!string.Equals(decision.PrecisionMode, "Alert", StringComparison.OrdinalIgnoreCase))
                factors.Add("PrecisionShadow");
            if (!string.Equals(decision.EffectiveMode, "Alert", StringComparison.OrdinalIgnoreCase)
                && factors.Count == 0)
                factors.Add("RuntimeGate");
            if (factors.Count == 0)
                factors.Add("AlertNotEmitted");

            // One gap can have multiple independent, simultaneously active gates.
            // The first cause is prioritized for sorting; the others remain visible
            // and must never be interpreted as automatic promotion eligibility.
            return factors;
        }

        private static bool HasReason(IEnumerable<string> reasons, string term)
            => reasons.Any(reason => reason.Contains(term, StringComparison.OrdinalIgnoreCase));
    }
}
