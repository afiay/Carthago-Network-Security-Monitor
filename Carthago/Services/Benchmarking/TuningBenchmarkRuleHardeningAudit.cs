// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkRuleHardeningAudit.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Full registered-rule inventory and explicit evidence state.
    /// A profile/metadata contract does not itself prove a detector's quality.
    /// </summary>
    public sealed class TuningBenchmarkRuleHardeningEntry
    {
        public string RuleId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Maturity { get; set; } = string.Empty;
        public string PrecisionDefaultMode { get; set; } = string.Empty;
        public string TuningTier { get; set; } = string.Empty;
        public int MinimumConfidence { get; set; }
        public int RequiredTelemetryKinds { get; set; }
        public int RequiredFields { get; set; }
        public int EvidenceFields { get; set; }
        public int PositiveCases { get; set; }
        public int PositiveRecognized { get; set; }
        public int ExplicitNegativeCases { get; set; }
        public int ExplicitNegativePassed { get; set; }
        public int BenignRawMatches { get; set; }
        public bool PairedSyntheticControls { get; set; }
        public bool BaselineRequired { get; set; }
        public string EvidenceStatus { get; set; } = string.Empty;
        public List<string> ContractIssues { get; set; } = new();
    }

    public static class TuningBenchmarkRuleHardeningAudit
    {
        public static List<TuningBenchmarkRuleHardeningEntry> Analyze(TuningBenchmarkReport report)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));
            var coverage = report.RuleEvidenceCoverage.ToDictionary(
                static entry => entry.RuleId, StringComparer.OrdinalIgnoreCase);

            var entries = new List<TuningBenchmarkRuleHardeningEntry>();
            foreach (var descriptor in RuleCatalog.All
                .OrderBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase))
            {
                var precision = RulePrecisionCatalog.GetProfile(descriptor);
                var tuning = RuleTuningCatalog.GetBaseDecision(descriptor.RuleId);
                coverage.TryGetValue(descriptor.RuleId, out var cases);

                var issues = new List<string>();
                if (precision.RequiredTelemetry.Count == 0)
                    issues.Add("MissingRequiredTelemetry");
                if (precision.RequiredFields.Count == 0)
                    issues.Add("MissingRequiredFields");
                if (precision.EvidenceFields.Count == 0)
                    issues.Add("MissingEvidenceFields");
                if (precision.PositiveConditions.Count == 0 || precision.NegativeConditions.Count == 0)
                    issues.Add("MissingPositiveOrNegativeContract");
                if (precision.MinimumConfidence is < 1 or > 100)
                    issues.Add("InvalidConfidenceFloor");
                if (precision.RequiredTests.Count == 0)
                    issues.Add("MissingTestPlan");
                if (tuning.RequiresBaseline && string.IsNullOrWhiteSpace(tuning.BaselineDependency))
                    issues.Add("MissingBaselineDependency");

                var positives = cases?.PositiveCases ?? 0;
                var negatives = cases?.ExplicitNegativeCases ?? 0;
                var evidenceStatus = positives > 0 && negatives > 0 ? "PairedSyntheticControls"
                    : positives > 0 ? "PositiveOnly"
                    : negatives > 0 ? "NegativeOnly"
                    : "NoExplicitReplayControls";

                entries.Add(new TuningBenchmarkRuleHardeningEntry
                {
                    RuleId = descriptor.RuleId,
                    Name = descriptor.Name,
                    Category = descriptor.Category,
                    Severity = descriptor.DefaultSeverity.ToString(),
                    Maturity = precision.Maturity.ToString(),
                    PrecisionDefaultMode = precision.DefaultMode.ToString(),
                    TuningTier = tuning.Tier.ToString(),
                    MinimumConfidence = precision.MinimumConfidence,
                    RequiredTelemetryKinds = precision.RequiredTelemetry.Count,
                    RequiredFields = precision.RequiredFields.Count,
                    EvidenceFields = precision.EvidenceFields.Count,
                    PositiveCases = positives,
                    PositiveRecognized = cases?.PositiveRecognized ?? 0,
                    ExplicitNegativeCases = negatives,
                    ExplicitNegativePassed = cases?.ExplicitNegativePassed ?? 0,
                    BenignRawMatches = cases?.BenignRawMatches ?? 0,
                    PairedSyntheticControls = positives > 0 && negatives > 0,
                    BaselineRequired = tuning.RequiresBaseline,
                    EvidenceStatus = evidenceStatus,
                    ContractIssues = issues
                });
            }
            return entries;
        }
    }
}
