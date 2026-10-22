// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleHealthSnapshot.cs
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Services.RuleTuning;
using Carthago.Services.Benchmarking;

namespace Carthago.Engine.Rules.Health
{
    public sealed record RuleHealthSnapshot(
        RuleDescriptor Descriptor,
        RuleIntelligence Intelligence,
        RulePrecisionProfile? PrecisionProfile,
        RuleQualityScore QualityScore,
        RuleRuntimeStats RuntimeStats,
        RuleTelemetryCoverageImpact TelemetryCoverage,
        IReadOnlyList<RuleCatalogValidationFinding> ValidationFindings,
        RuleMode CurrentMode)
    {
        public RuleNoMatchStats NoMatchStats { get; init; } = RuleNoMatchStats.Empty(string.Empty);
        public RuleTuningInsight TuningInsight { get; init; } = RuleTuningInsight.Empty(string.Empty);
        public RuleSuppressionPolicyStats SuppressionPolicyStats { get; init; } = RuleSuppressionPolicyStats.Empty(string.Empty);
        public IReadOnlyList<RuleSuppressionPolicy> ActiveSuppressionPolicies { get; init; } = System.Array.Empty<RuleSuppressionPolicy>();
        public RuleReplayCoverageSnapshot ReplayCoverage { get; init; } = RuleReplayCoverageSnapshot.Empty(string.Empty);

        public string RuleId => Descriptor.RuleId;
        public string Name => Descriptor.Name;
        public string Category => Descriptor.Category;
        public bool HasCriticalValidationErrors => ValidationFindings.Any(static finding => finding.IsCritical);
        public bool HasValidationErrors => ValidationFindings.Any(static finding => finding.IsError);
    }
}
