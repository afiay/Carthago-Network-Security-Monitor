// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/CompiledContentPackProviderBase.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal abstract class CompiledContentPackProviderBase : IContentPackProvider
    {
        private static readonly Lazy<IReadOnlyDictionary<string, IDetectionRule>> CoreRules = new(() =>
            RuleRegistry.CreateDefaultRules().ToDictionary(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase));

        private readonly Lazy<IReadOnlyList<ContentPackRuleRegistration>> _registrations;

        protected CompiledContentPackProviderBase()
            => _registrations = new Lazy<IReadOnlyList<ContentPackRuleRegistration>>(BuildRegistrations);

        public abstract ContentPackManifest Manifest { get; }

        public IReadOnlyList<ContentPackRuleRegistration> GetRuleRegistrations()
            => _registrations.Value;

        protected static IEnumerable<string> Range(int startInclusive, int endInclusive)
        {
            for (var value = startInclusive; value <= endInclusive; value++)
                yield return $"R{value:000}";
        }

        protected static IEnumerable<string> Concat(params IEnumerable<string>[] groups)
            => groups.SelectMany(static group => group);

        protected static ContentPackRule AliasRule(string packRuleId, string sourceRuleId, string category)
        {
            var source = CoreRules.Value[sourceRuleId];
            return new ContentPackRule
            {
                RuleId = packRuleId,
                Name = source.Descriptor.Name,
                Category = category,
                Description = source.Descriptor.Description,
                DefaultSeverity = source.Descriptor.DefaultSeverity,
                Source = new ContentPackRuleSource { CoreRuleId = sourceRuleId },
                References = source.Intelligence.References.Take(4).ToList(),
                KnownFalsePositives = source.Intelligence.KnownFalsePositives.Take(4).ToList(),
                TelemetryRequirements = source.Intelligence.TelemetryRequirements.ToList()
            };
        }

        protected static List<ContentPackRule> AliasRules(string prefix, IEnumerable<string> sourceRuleIds, string category)
        {
            var rules = new List<ContentPackRule>();
            var index = 1;
            foreach (var sourceRuleId in sourceRuleIds)
            {
                rules.Add(AliasRule($"{prefix}{index:000}", sourceRuleId, category));
                index++;
            }

            return rules;
        }

        protected static List<ContentPackProfileDefaults> Profiles(params ContentPackProfileDefaults[] profiles)
            => profiles.ToList();

        protected static ContentPackProfileDefaults Profile(string name, RuleMode mode, double? confidenceFloor, string notes, params string[] requiredApprovedAssets)
            => new()
            {
                ProfileName = name,
                DefaultMode = mode,
                ConfidenceFloorForAlert = confidenceFloor,
                Notes = notes,
                RequiredApprovedAssets = requiredApprovedAssets.ToList(),
                DisableWhenTelemetryMissing = true
            };

        protected static List<ContentPackReplaySampleReference> Samples(params ContentPackReplaySampleReference[] samples)
            => samples.ToList();

        protected static ContentPackReplaySampleReference Sample(string id, string relativePath, ReplaySampleClassification classification, string purpose, params string[] expectedRuleIds)
            => new()
            {
                SampleId = id,
                RelativePath = relativePath,
                Classification = classification,
                Purpose = purpose,
                ExpectedRuleIds = expectedRuleIds.ToList()
            };

        protected static List<ContentPackBenchmarkExpectation> BenchmarkExpectations(params ContentPackBenchmarkExpectation[] expectations)
            => expectations.ToList();

        protected static ContentPackBenchmarkExpectation Benchmark(string profileName, double minPositivePassRate, int maxCriticalFalsePositives)
            => new()
            {
                ProfileName = profileName,
                MinimumPositivePassRate = minPositivePassRate,
                MaximumCriticalFalsePositives = maxCriticalFalsePositives,
                RequireBenchmarkBeforeAlertPromotion = true
            };

        protected static List<ContentPackHuntReference> Hunts(params ContentPackHuntReference[] hunts)
            => hunts.ToList();

        protected static ContentPackHuntReference Hunt(string id, string name, string description, string primaryRuleId, double? minConfidence = null)
            => new()
            {
                HuntId = id,
                Name = name,
                Description = description,
                PrimaryRuleId = primaryRuleId,
                MinConfidence = minConfidence
            };

        protected static List<ContentPackResponseRecommendation> Recommendations(params ContentPackResponseRecommendation[] recommendations)
            => recommendations.ToList();

        protected static ContentPackResponseRecommendation Recommend(
            string id,
            string title,
            string description,
            ResponseActionType actionType,
            ResponseActionSafety safety,
            string safetyWarning,
            IEnumerable<string> appliesToRuleIds,
            params string[] steps)
            => new()
            {
                RecommendationId = id,
                Title = title,
                Description = description,
                ActionType = actionType,
                Safety = safety,
                RequiresApproval = safety == ResponseActionSafety.Destructive || safety == ResponseActionSafety.ApprovalRequired,
                SafetyWarning = safetyWarning,
                AppliesToRuleIds = appliesToRuleIds.ToList(),
                Steps = steps.ToList()
            };

        protected static List<ContentPackDashboardPreset> Presets(params ContentPackDashboardPreset[] presets)
            => presets.ToList();

        protected static ContentPackDashboardPreset Preset(string id, string name, string description, string profileName, params (string Key, string Value)[] filters)
            => new()
            {
                PresetId = id,
                Name = name,
                Description = description,
                ProfileName = profileName,
                Filters = filters.ToDictionary(static filter => filter.Key, static filter => filter.Value, StringComparer.OrdinalIgnoreCase)
            };

        protected static List<ContentPackTuningDefaults> Overrides(params ContentPackTuningDefaults[] overrides)
            => overrides.ToList();

        protected static ContentPackTuningDefaults Override(string ruleId, RuleMode? mode = null, int? threshold = null, int? windowSeconds = null, double? confidenceFloor = null, string notes = "")
            => new()
            {
                RuleId = ruleId,
                RecommendedMode = mode,
                Threshold = threshold,
                WindowSeconds = windowSeconds,
                ConfidenceFloor = confidenceFloor,
                Notes = notes
            };

        protected static List<RuleReference> References(params RuleReference[] references)
            => references.ToList();

        protected static RuleReference Ref(string source, string title, string url, string? externalId = null)
            => new(source, title, url, externalId);

        private IReadOnlyList<ContentPackRuleRegistration> BuildRegistrations()
        {
            return Manifest.Rules.Select(rule =>
            {
                var sourceRule = CoreRules.Value[rule.Source.CoreRuleId];
                return new ContentPackRuleRegistration
                {
                    PackId = Manifest.PackId,
                    PackVersion = Manifest.Version,
                    Rule = rule,
                    CompiledRule = new CompiledContentPackRule(Manifest.PackId, rule, sourceRule)
                };
            }).ToArray();
        }
    }
}
