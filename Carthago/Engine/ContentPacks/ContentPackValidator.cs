// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackValidator.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackValidator
    {
        public ContentPackValidationResult Validate(
            ContentPackManifest manifest,
            IEnumerable<string>? existingPackIds = null,
            IEnumerable<string>? installedCoreRuleIds = null)
        {
            var result = new ContentPackValidationResult();
            if (manifest == null)
            {
                result.Errors.Add("Manifest is null.");
                return result;
            }

            var rules = manifest.Rules ?? new List<ContentPackRule>();
            var profiles = manifest.Profiles ?? new List<ContentPackProfileDefaults>();
            var tuningDefaults = manifest.TuningDefaults ?? new List<ContentPackTuningDefaults>();
            var existingRuleOverrides = manifest.ExistingRuleOverrides ?? new List<ContentPackTuningDefaults>();
            var replaySamples = manifest.ReplaySamples ?? new List<ContentPackReplaySampleReference>();
            var responseRecommendations = manifest.ResponseRecommendations ?? new List<ContentPackResponseRecommendation>();
            var references = manifest.References ?? new List<RuleReference>();
            var installOperations = manifest.InstallOperations ?? new List<string>();

            var knownCoreRuleIds = (installedCoreRuleIds ?? RuleCatalog.All.Select(static descriptor => descriptor.RuleId))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var knownManifestRuleIds = rules
                .Where(static rule => rule != null && !string.IsNullOrWhiteSpace(rule.RuleId))
                .Select(static rule => rule.RuleId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(manifest.PackId))
                result.Errors.Add("PackId is required.");
            if ((existingPackIds ?? Array.Empty<string>()).Contains(manifest.PackId, StringComparer.OrdinalIgnoreCase))
                result.Errors.Add($"Duplicate content pack id: {manifest.PackId}");
            if (string.IsNullOrWhiteSpace(manifest.Name))
                result.Errors.Add("Name is required.");
            if (!TryParseVersion(manifest.Version, out _))
                result.Errors.Add($"Invalid semantic version: {manifest.Version}");
            if (!TryParseVersion(manifest.MinimumCarthagoVersion, out var minimumVersion))
                result.Errors.Add($"Invalid minimum Carthago version: {manifest.MinimumCarthagoVersion}");
            else if (minimumVersion > ContentPackConstants.CurrentCarthagoVersion)
                result.Errors.Add($"Pack requires unsupported Carthago version {minimumVersion}.");

            if (manifest.DisableMandatoryJournaling)
                result.Errors.Add("Content packs cannot disable mandatory journaling.");

            if (installOperations.Any(static operation =>
                    !string.IsNullOrWhiteSpace(operation) && ContentPackConstants.DangerousInstallOperationKeywords.Any(keyword => operation.Contains(keyword, StringComparison.OrdinalIgnoreCase))))
            {
                result.Errors.Add("Unsafe install operations are not allowed in content packs.");
            }

            var duplicateRuleIds = rules
                .Where(static rule => rule != null && !string.IsNullOrWhiteSpace(rule.RuleId))
                .GroupBy(static rule => rule.RuleId, StringComparer.OrdinalIgnoreCase)
                .Where(static group => group.Count() > 1)
                .Select(static group => group.Key)
                .ToArray();
            if (duplicateRuleIds.Length > 0)
                result.Errors.Add("Duplicate pack rule IDs: " + string.Join(", ", duplicateRuleIds));

            foreach (var rule in rules)
            {
                if (rule == null)
                {
                    result.Errors.Add("Manifest contains a null rule entry.");
                    continue;
                }

                if (!RuleIdValidator.IsPackRuleId(rule.RuleId))
                    result.Errors.Add($"Invalid pack rule ID format: {rule.RuleId}");
                if (knownCoreRuleIds.Contains(rule.RuleId))
                    result.Errors.Add($"Pack rule ID collides with core rule ID: {rule.RuleId}");

                var coreRuleId = rule.Source?.CoreRuleId;
                if (string.IsNullOrWhiteSpace(coreRuleId))
                    result.Errors.Add($"{rule.RuleId} must reference a compiled core detector source.");
                else if (!knownCoreRuleIds.Contains(coreRuleId))
                    result.Errors.Add($"{rule.RuleId} references unknown source rule {coreRuleId}.");
            }

            foreach (var profile in profiles)
            {
                if (profile == null)
                {
                    result.Errors.Add("Manifest contains a null profile entry.");
                    continue;
                }

                if (!RuleTuningCatalog.IsKnownProfile(profile.ProfileName))
                    result.Errors.Add($"Unknown profile default: {profile.ProfileName}");
            }

            foreach (var tuning in tuningDefaults)
            {
                if (tuning == null)
                {
                    result.Errors.Add("Manifest contains a null tuning default entry.");
                    continue;
                }

                if (!knownManifestRuleIds.Contains(tuning.RuleId))
                    result.Errors.Add($"Tuning default references unknown pack rule ID: {tuning.RuleId}");
                ValidateFieldOverrides(tuning.RuleId, tuning.FieldOverrides ?? new Dictionary<string, string>(), isExistingCoreOverride: false, result);
            }

            foreach (var existingOverride in existingRuleOverrides)
            {
                if (existingOverride == null)
                {
                    result.Errors.Add("Manifest contains a null existing-rule override entry.");
                    continue;
                }

                if (!knownCoreRuleIds.Contains(existingOverride.RuleId))
                    result.Errors.Add($"ExistingRuleOverrides references unknown core rule ID: {existingOverride.RuleId}");
                ValidateFieldOverrides(existingOverride.RuleId, existingOverride.FieldOverrides ?? new Dictionary<string, string>(), isExistingCoreOverride: true, result);
            }

            foreach (var replay in replaySamples)
            {
                if (replay == null)
                {
                    result.Errors.Add("Manifest contains a null replay sample entry.");
                    continue;
                }

                foreach (var expectedRuleId in replay.ExpectedRuleIds ?? new List<string>())
                {
                    if (!knownManifestRuleIds.Contains(expectedRuleId))
                        result.Errors.Add($"Replay sample {replay.SampleId} references unknown pack rule {expectedRuleId}.");
                }
            }

            foreach (var response in responseRecommendations)
            {
                if (response == null)
                {
                    result.Errors.Add("Manifest contains a null response recommendation entry.");
                    continue;
                }

                var destructive = response.Safety == ResponseActionSafety.Destructive
                    || response.ActionType is ResponseActionType.BlockIp
                        or ResponseActionType.BlockDomain
                        or ResponseActionType.IsolateHost
                        or ResponseActionType.DisableRule
                        or ResponseActionType.ChangeProfile
                        or ResponseActionType.ClearBaseline
                        or ResponseActionType.DeleteFeedback
                        or ResponseActionType.PurgeJournalOutbox;
                if (destructive && response.Automatic)
                    result.Errors.Add($"Recommendation {response.RecommendationId} cannot define destructive automatic execution.");
            }

            if (responseRecommendations.Count == 0)
                result.Warnings.Add("Pack does not define response recommendations.");

            if (references.Count == 0)
                result.Warnings.Add("Pack does not define external references.");

            return result;
        }

        private static void ValidateFieldOverrides(string ruleId, IReadOnlyDictionary<string, string> fieldOverrides, bool isExistingCoreOverride, ContentPackValidationResult result)
        {
            foreach (var field in fieldOverrides.Keys)
            {
                if (ContentPackConstants.ImmutableOverrideFields.Contains(field, StringComparer.OrdinalIgnoreCase))
                    result.Errors.Add($"Rule {ruleId} attempts to override immutable field {field}.");
                if (field.Contains("ui", StringComparison.OrdinalIgnoreCase) || field.Contains("dashboard", StringComparison.OrdinalIgnoreCase))
                    result.Errors.Add($"Rule {ruleId} attempts to modify UI preferences through rule configuration: {field}.");
                if (!isExistingCoreOverride && field.Equals("Mode", StringComparison.OrdinalIgnoreCase))
                    continue;
            }
        }

        private static bool TryParseVersion(string value, out Version version)
            => Version.TryParse((value ?? string.Empty).Split('-', '+')[0], out version!);
    }
}
