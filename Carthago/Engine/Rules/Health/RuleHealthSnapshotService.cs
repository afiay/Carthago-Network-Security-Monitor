// SPDX-License-Identifier: MIT
// File: Engine/Rules/Health/RuleHealthSnapshotService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;
using Carthago.Services;
using Carthago.Engine.Rules;
using Carthago.Services.RuleTuning;
using Carthago.Services.Benchmarking;

namespace Carthago.Engine.Rules.Health
{
    public sealed class RuleHealthSnapshotService
    {
        private readonly RuleCatalogValidator _validator;
        private readonly RuleQualityScorer _qualityScorer;
        private readonly RuleTelemetryCoverageService _telemetryCoverageService;
        private readonly Func<IReadOnlyList<IDetectionRule>> _ruleProvider;
        private readonly Func<RuleReplayDirectoryResult?> _replayResultProvider;

        public RuleHealthSnapshotService(
            RuleCatalogValidator? validator = null,
            RuleQualityScorer? qualityScorer = null,
            Func<IReadOnlyList<IDetectionRule>>? ruleProvider = null,
            Func<RuleReplayDirectoryResult?>? replayResultProvider = null)
        {
            _validator = validator ?? new RuleCatalogValidator();
            _qualityScorer = qualityScorer ?? new RuleQualityScorer();
            _ruleProvider = ruleProvider ?? (() => RuleRegistry.CreateDefaultRules());
            _replayResultProvider = replayResultProvider ?? (() => null);
            _telemetryCoverageService = new RuleTelemetryCoverageService(_ruleProvider);
        }

        public IReadOnlyList<RuleHealthSnapshot> Snapshot()
        {
            var rules = _ruleProvider().OrderBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase).ToArray();
            var validationReport = _validator.Validate(rules);
            var replayCoverageByRule = new RuleReplayCoverageService().Build(_replayResultProvider(), rules.Select(static rule => rule.Descriptor));
            var tuningInsightService = new RuleTuningInsightService();
            var findingsByRuleId = validationReport.Findings
                .Where(static finding => !string.IsNullOrWhiteSpace(finding.RuleId))
                .GroupBy(static finding => finding.RuleId!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => (IReadOnlyList<RuleCatalogValidationFinding>)group.ToArray(), StringComparer.OrdinalIgnoreCase);

            return rules.Select(rule =>
            {
                var runtime = RuleRuntimeStatsStore.Snapshot(rule.Descriptor.RuleId);
                var quality = _qualityScorer.Score(rule, validationReport, runtime);
                var currentMode = RuleEngine.GetRuleMode(rule.Descriptor.RuleId, rule.Descriptor.EnabledByDefault);
                var telemetryCoverage = _telemetryCoverageService.GetImpact(rule);
                var findings = findingsByRuleId.TryGetValue(rule.Descriptor.RuleId, out var list) ? list : Array.Empty<RuleCatalogValidationFinding>();
                var noMatchStats = RuleNoMatchReasonStore.Snapshot(rule.Descriptor.RuleId);
                var suppressionPolicyStats = RuleSuppressionAuditStore.Snapshot(rule.Descriptor.RuleId);
                var activeSuppressionPolicies = RuleSuppressionPolicyStore.Current.GetPoliciesForRule(rule.Descriptor.RuleId);
                var replayCoverage = replayCoverageByRule.TryGetValue(rule.Descriptor.RuleId, out var replayCoverageSnapshot)
                    ? replayCoverageSnapshot
                    : RuleReplayCoverageSnapshot.Empty(rule.Descriptor.RuleId);
                var tuningInsight = tuningInsightService.Build(rule, runtime, noMatchStats, telemetryCoverage, currentMode, findings);
                return new RuleHealthSnapshot(
                    rule.Descriptor,
                    rule.Intelligence,
                    rule.Intelligence?.PrecisionProfile ?? RulePrecisionCatalog.GetProfile(rule.Descriptor),
                    quality,
                    runtime,
                    telemetryCoverage,
                    findings,
                    currentMode)
                {
                    NoMatchStats = noMatchStats,
                    TuningInsight = tuningInsight,
                    SuppressionPolicyStats = suppressionPolicyStats,
                    ActiveSuppressionPolicies = activeSuppressionPolicies,
                    ReplayCoverage = replayCoverage
                };
            }).ToArray();
        }

        public RuleCatalogValidationReport ValidateCatalog()
            => _validator.Validate(_ruleProvider());
    }
}
