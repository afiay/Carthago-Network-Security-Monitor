// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleQualityScore.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Services.Diagnostics;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Health
{
    public enum RuleQualityGrade
    {
        Weak,
        NeedsWork,
        Good,
        Excellent
    }

    public sealed record RuleQualityDimensionScore(
        string Dimension,
        int Score,
        IReadOnlyList<string> Reasons,
        IReadOnlyList<string> RecommendedImprovements);

    public sealed record RuleQualityScore(
        string RuleId,
        int TotalScore,
        RuleQualityGrade Grade,
        IReadOnlyList<RuleQualityDimensionScore> DimensionScores,
        IReadOnlyList<string> Reasons,
        IReadOnlyList<string> RecommendedImprovements);

    public sealed class RuleQualityScorer
    {
        public RuleQualityScore Score(IDetectionRule rule, RuleCatalogValidationReport? validationReport = null, RuleRuntimeStats? runtimeStats = null)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));

            var descriptor = rule.Descriptor;
            var intelligence = rule.Intelligence;
            var profile = intelligence?.PrecisionProfile ?? RulePrecisionCatalog.GetProfile(descriptor);
            var ruleFindings = validationReport?.Findings
                .Where(finding => string.Equals(finding.RuleId, descriptor.RuleId, StringComparison.OrdinalIgnoreCase))
                .ToArray() ?? Array.Empty<RuleCatalogValidationFinding>();

            var dimensions = new List<RuleQualityDimensionScore>
            {
                ScoreMetadata(descriptor, intelligence, ruleFindings),
                ScoreTelemetry(profile, intelligence, ruleFindings),
                ScoreEvidence(profile, ruleFindings),
                ScoreFalsePositiveControl(profile, intelligence, ruleFindings),
                ScoreAnalystWorkflow(profile, intelligence, ruleFindings),
                ScoreTestability(profile, ruleFindings),
                ScoreRuntimeHealth(runtimeStats),
                ScoreStateAndPolicy(profile, ruleFindings)
            };

            var total = (int)Math.Clamp(Math.Round(dimensions.Average(static score => score.Score)), 0, 100);
            var grade = total >= 90 ? RuleQualityGrade.Excellent
                : total >= 75 ? RuleQualityGrade.Good
                : total >= 55 ? RuleQualityGrade.NeedsWork
                : RuleQualityGrade.Weak;

            var reasons = dimensions.SelectMany(static dimension => dimension.Reasons.Select(reason => $"{dimension.Dimension}: {reason}")).Take(20).ToArray();
            var improvements = dimensions
                .Where(static dimension => dimension.Score < 90)
                .SelectMany(static dimension => dimension.RecommendedImprovements.Select(improvement => $"{dimension.Dimension}: {improvement}"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(20)
                .ToArray();

            return new RuleQualityScore(descriptor.RuleId, total, grade, dimensions, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreMetadata(RuleDescriptor descriptor, RuleIntelligence? intelligence, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "Metadata", ref score, reasons, improvements);
            if (string.IsNullOrWhiteSpace(descriptor.Description) || descriptor.Description.Length < 32)
            {
                score -= 10;
                reasons.Add("Description is short or absent.");
                improvements.Add("Add a concise behavior-focused description.");
            }
            if (intelligence?.References == null || intelligence.References.Count == 0)
            {
                score -= 8;
                reasons.Add("No external or internal references are attached.");
                improvements.Add("Attach references for analyst trust and future export.");
            }
            if (intelligence?.AttackTechniqueIds == null || intelligence.AttackTechniqueIds.Count == 0)
            {
                score -= 5;
                improvements.Add("Map the rule to ATT&CK or an internal tactic when possible.");
            }

            return Build("Metadata", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreTelemetry(RulePrecisionProfile? profile, RuleIntelligence? intelligence, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "Telemetry", ref score, reasons, improvements);
            if (profile == null)
            {
                return Build("Telemetry", 0, new[] { "No precision profile exists." }, new[] { "Create a RulePrecisionProfile with required telemetry and fields." });
            }
            if (profile.RequiredTelemetry.Count < 1)
            {
                score -= 40;
                improvements.Add("Declare at least one telemetry kind.");
            }
            if (profile.RequiredFields.Count < 2)
            {
                score -= 20;
                improvements.Add("Declare concrete required fields beyond generic text.");
            }
            if (intelligence?.TelemetryRequirements != null && intelligence.TelemetryRequirements.Count >= profile.RequiredTelemetry.Count)
                reasons.Add("Rule exposes analyst-readable telemetry requirements.");

            return Build("Telemetry", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreEvidence(RulePrecisionProfile? profile, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "Evidence", ref score, reasons, improvements);
            if (profile == null)
                return Build("Evidence", 0, new[] { "No precision profile exists." }, new[] { "Add positive and negative evidence gates." });

            if (profile.EvidenceFields.Count < 3)
            {
                score -= 20;
                improvements.Add("Add structured evidence fields that explain source, destination, indicator, and threshold.");
            }
            if (profile.PositiveConditions.Count < 1)
            {
                score -= 25;
                improvements.Add("Add positive evidence conditions.");
            }
            if (profile.NegativeConditions.Count < 1)
            {
                score -= 20;
                improvements.Add("Add negative gates to prevent text-only or port-only matches.");
            }
            if (profile.MinimumConfidence < 50)
            {
                score -= 10;
                improvements.Add("Raise or justify the minimum confidence floor.");
            }

            return Build("Evidence", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreFalsePositiveControl(RulePrecisionProfile? profile, RuleIntelligence? intelligence, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "FalsePositiveControl", ref score, reasons, improvements);
            var notes = Math.Max(profile?.FalsePositiveNotes.Count ?? 0, intelligence?.KnownFalsePositives.Count ?? 0);
            if (notes == 0)
            {
                score -= 35;
                improvements.Add("Add common benign causes and tuning guidance.");
            }
            if (profile?.Cooldown == null)
            {
                score -= 8;
                improvements.Add("Declare a cooldown for rules that can fire repeatedly.");
            }
            if (profile?.TuningKnobs == null || profile.TuningKnobs.Count == 0)
            {
                score -= 12;
                improvements.Add("Expose tuning knobs for severity, threshold, window, and approved assets.");
            }

            return Build("FalsePositiveControl", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreAnalystWorkflow(RulePrecisionProfile? profile, RuleIntelligence? intelligence, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "AnalystWorkflow", ref score, reasons, improvements);
            if (string.IsNullOrWhiteSpace(intelligence?.InvestigationHint))
            {
                score -= 30;
                improvements.Add("Add an investigation hint that tells the analyst what to verify first.");
            }
            if (string.IsNullOrWhiteSpace(intelligence?.TuningHint))
            {
                score -= 12;
                improvements.Add("Add tuning guidance for noisy environments.");
            }
            if (profile?.RequiredEnvironmentConfig != null && profile.RequiredEnvironmentConfig.Count > 0)
                reasons.Add("Rule declares environment prerequisites.");

            return Build("AnalystWorkflow", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreTestability(RulePrecisionProfile? profile, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "Testability", ref score, reasons, improvements);
            if (profile == null || profile.RequiredTests.Count == 0)
            {
                score -= 40;
                improvements.Add("Declare required positive, benign, missing-telemetry, and confidence-floor tests.");
            }
            else if (profile.RequiredTests.Count < 4)
            {
                score -= 12;
                improvements.Add("Add at least four required test categories.");
            }

            return Build("Testability", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreRuntimeHealth(RuleRuntimeStats? stats)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();
            if (stats == null || stats.Evaluations == 0)
            {
                reasons.Add("No runtime data observed yet.");
                improvements.Add("Run replay tests or live traffic to establish runtime health.");
                return Build("RuntimeHealth", 80, reasons, improvements);
            }

            if (stats.Failed > 0)
            {
                score -= Math.Min(30, (int)stats.Failed * 6);
                improvements.Add("Investigate rule exceptions and failure paths.");
            }
            if (stats.MissingTelemetryCount > stats.Evaluations / 2)
            {
                score -= 18;
                improvements.Add("Check telemetry coverage or selector metadata for this rule.");
            }
            if (stats.AverageDurationMicroseconds > 2_000)
            {
                score -= 12;
                improvements.Add("Profile and optimize expensive rule evaluation.");
            }
            if (stats.Matches > 0 && stats.Suppressed > stats.Matches / 2)
            {
                score -= 10;
                improvements.Add("Review suppressions; high suppression can hide noisy or over-broad logic.");
            }

            return Build("RuntimeHealth", score, reasons, improvements);
        }

        private static RuleQualityDimensionScore ScoreStateAndPolicy(RulePrecisionProfile? profile, IReadOnlyList<RuleCatalogValidationFinding> findings)
        {
            var score = 100;
            var reasons = new List<string>();
            var improvements = new List<string>();

            Penalize(findings, "Statefulness", ref score, reasons, improvements);
            Penalize(findings, "EnvironmentPolicy", ref score, reasons, improvements);
            if (profile?.Window != null || profile?.Threshold != null || !string.IsNullOrWhiteSpace(profile?.DistinctBy))
                reasons.Add("Rule declares state/window behavior.");
            if (profile?.RequiredEnvironmentConfig != null && profile.RequiredEnvironmentConfig.Count > 0)
                reasons.Add("Rule declares environment policy dependencies.");

            return Build("StateAndPolicy", score, reasons, improvements);
        }

        private static void Penalize(IReadOnlyList<RuleCatalogValidationFinding> findings, string dimension, ref int score, List<string> reasons, List<string> improvements)
        {
            foreach (var finding in findings.Where(finding => string.Equals(finding.Dimension, dimension, StringComparison.OrdinalIgnoreCase)))
            {
                var penalty = finding.Severity switch
                {
                    RuleCatalogValidationSeverity.Critical => 50,
                    RuleCatalogValidationSeverity.Error => 35,
                    RuleCatalogValidationSeverity.Warning => 15,
                    _ => 5
                };
                score -= penalty;
                reasons.Add(finding.Message);
                improvements.Add($"Resolve validation finding {finding.Code}.");
            }
        }

        private static RuleQualityDimensionScore Build(string dimension, int score, IEnumerable<string> reasons, IEnumerable<string> improvements)
            => new(dimension, (int)Math.Clamp(score, 0, 100), reasons.Where(static value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), improvements.Where(static value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }
}
