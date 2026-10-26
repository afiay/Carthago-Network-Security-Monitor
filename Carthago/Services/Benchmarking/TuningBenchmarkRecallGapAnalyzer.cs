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
                            evidence.AddRange(decision.ReasonDetails);
                            evidence.AddRange(decision.RuntimePrecisionReasons);
                            if (evidence.Count == 0)
                                evidence.AddRange(decision.Reasons);
                        }

                        gaps.Add(new TuningBenchmarkRecallGap
                        {
                            ProfileName = profile.Key,
                            SampleName = sample.Name,
                            RuleId = ruleId,
                            Cause = Classify(matched, outcome, decision),
                            DetectionOutcome = outcome,
                            EffectiveMode = decision?.EffectiveMode ?? "NoDecision",
                            Confidence = decision?.Confidence,
                            ConfidenceFloor = decision?.ConfidenceFloor,
                            Evidence = evidence.Where(static item => !string.IsNullOrWhiteSpace(item))
                                .Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList()
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

        private static string Classify(bool matched, string outcome, TuningBenchmarkRuleDecision? decision)
        {
            if (!matched)
                return outcome switch
                {
                    "MissingTelemetry" => "MissingTelemetry",
                    "EvaluationFailed" => "DetectorFailure",
                    "RuleUnavailable" => "RuleUnavailable",
                    _ => "NoMatch"
                };

            if (decision == null)
                return "NoPolicyDecision";
            if (decision.Reasons.Any(static reason =>
                reason.Contains("ApprovedAssetMatched", StringComparison.OrdinalIgnoreCase)))
                return "ApprovedAsset";
            if (decision.Reasons.Any(static reason =>
                reason.Contains("ConfidenceFloorApplied", StringComparison.OrdinalIgnoreCase)))
                return "ConfidenceFloor";
            if (string.Equals(decision.EffectiveMode, "Disabled", StringComparison.OrdinalIgnoreCase))
                return "Disabled";
            if (!string.Equals(decision.DefaultMode, "Alert", StringComparison.OrdinalIgnoreCase))
                return "ProfileShadow";
            if (!string.Equals(decision.PrecisionMode, "Alert", StringComparison.OrdinalIgnoreCase))
                return "PrecisionShadow";
            if (!string.Equals(decision.EffectiveMode, "Alert", StringComparison.OrdinalIgnoreCase))
                return "RuntimeGate";

            return "AlertNotEmitted";
        }
    }
}
