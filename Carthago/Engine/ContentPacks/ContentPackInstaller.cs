// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackInstaller.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackInstaller
    {
        private readonly ContentPackRegistry _registry;
        private readonly ContentPackValidator _validator;
        private readonly ContentPackBenchmarkRunner _benchmarkRunner;

        public ContentPackInstaller(
            ContentPackRegistry? registry = null,
            ContentPackValidator? validator = null,
            ContentPackBenchmarkRunner? benchmarkRunner = null)
        {
            _registry = registry ?? new ContentPackRegistry();
            _validator = validator ?? new ContentPackValidator();
            _benchmarkRunner = benchmarkRunner ?? new ContentPackBenchmarkRunner(_registry);
        }

        public ContentPackInstallPlan DryRun(ContentPackManifest manifest, bool enableAfterInstall = false)
        {
            var state = _registry.LoadState();
            var validation = _validator.Validate(
                manifest,
                state.InstalledPacks
                    .Select(static pack => pack.PackId)
                    .Where(packId => !string.Equals(packId, manifest.PackId, StringComparison.OrdinalIgnoreCase)));
            var plan = BuildPlan(manifest, validation, enableAfterInstall);
            state.DryRunPlanHistory.Add(plan);
            _registry.Store.Save(state);
            return plan;
        }

        public ContentPackInstallResult Install(ContentPackManifest manifest, bool enableAfterInstall = false, bool runBenchmark = false, string benchmarkOutputDirectory = "build-verify")
        {
            var plan = DryRun(manifest, enableAfterInstall);
            if (!plan.Validation.IsValid)
                return new ContentPackInstallResult
                {
                    PackId = manifest.PackId,
                    Version = manifest.Version,
                    Plan = plan,
                    Errors = plan.Validation.Errors.ToList()
                };

            var state = _registry.LoadState();
            _registry.Store.SaveManifest(manifest);
            var installed = state.InstalledPacks.FirstOrDefault(item => string.Equals(item.PackId, manifest.PackId, StringComparison.OrdinalIgnoreCase));
            if (installed == null)
            {
                installed = new InstalledContentPackState();
                state.InstalledPacks.Add(installed);
            }

            installed.PackId = manifest.PackId;
            installed.Name = manifest.Name;
            installed.Version = manifest.Version;
            installed.Enabled = enableAfterInstall;
            installed.InstalledAtUtc = DateTime.UtcNow;
            installed.LastEnabledAtUtc = enableAfterInstall ? DateTime.UtcNow : installed.LastEnabledAtUtc;
            installed.ValidationResult = plan.Validation;
            installed.InstalledRuleIds = manifest.Rules.Select(static rule => rule.RuleId).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList();
            installed.ActivatedProfileChanges = plan.ProfileChanges;
            installed.AppliedTuningChanges = plan.TuningChanges;
            installed.DryRunPlanHistory.Add(plan);
            installed.Changelog = manifest.Changelog.ToList();
            installed.ManifestPath = _registry.Store.GetManifestPath(manifest.PackId);

            if (enableAfterInstall && runBenchmark)
                installed.LastBenchmarkResult = _benchmarkRunner.Run(manifest.PackId, benchmarkOutputDirectory);

            _registry.Store.Save(state);

            return new ContentPackInstallResult
            {
                PackId = manifest.PackId,
                Version = manifest.Version,
                Plan = plan,
                InstalledPack = installed
            };
        }

        public ContentPackInstallResult Enable(string packId, bool runBenchmark = false, string benchmarkOutputDirectory = "build-verify")
        {
            var state = _registry.LoadState();
            var installed = state.InstalledPacks.FirstOrDefault(item => string.Equals(item.PackId, packId, StringComparison.OrdinalIgnoreCase));
            if (installed == null)
            {
                return new ContentPackInstallResult
                {
                    PackId = packId,
                    Errors = { $"Pack {packId} is not installed." }
                };
            }

            installed.Enabled = true;
            installed.LastEnabledAtUtc = DateTime.UtcNow;
            if (runBenchmark)
                installed.LastBenchmarkResult = _benchmarkRunner.Run(packId, benchmarkOutputDirectory);
            _registry.Store.Save(state);

            return new ContentPackInstallResult
            {
                PackId = installed.PackId,
                Version = installed.Version,
                InstalledPack = installed,
                Plan = new ContentPackInstallPlan
                {
                    PackId = installed.PackId,
                    Version = installed.Version,
                    DryRun = false,
                    PlannedChanges = { "Activated compiled content pack rules.", "Preserved explicit user rule overrides." }
                }
            };
        }

        public ContentPackInstallResult Disable(string packId)
        {
            var state = _registry.LoadState();
            var installed = state.InstalledPacks.FirstOrDefault(item => string.Equals(item.PackId, packId, StringComparison.OrdinalIgnoreCase));
            if (installed == null)
            {
                return new ContentPackInstallResult
                {
                    PackId = packId,
                    Errors = { $"Pack {packId} is not installed." }
                };
            }

            installed.Enabled = false;
            installed.HistoricalWarnings.Add("Pack disabled. Historical detections, journals, incidents, and feedback were preserved.");
            _registry.Store.Save(state);

            return new ContentPackInstallResult
            {
                PackId = installed.PackId,
                Version = installed.Version,
                InstalledPack = installed,
                Plan = new ContentPackInstallPlan
                {
                    PackId = installed.PackId,
                    Version = installed.Version,
                    DryRun = false,
                    PlannedChanges = { "Stopped future content-pack rule activation without deleting historical records." }
                }
            };
        }

        public ContentPackUpgradePlan PlanUpgrade(ContentPackManifest targetManifest, bool allowDowngrade = false)
        {
            var state = _registry.LoadState();
            var installed = state.InstalledPacks.FirstOrDefault(item => string.Equals(item.PackId, targetManifest.PackId, StringComparison.OrdinalIgnoreCase));
            var plan = new ContentPackUpgradePlan
            {
                PackId = targetManifest.PackId,
                CurrentVersion = installed?.Version ?? "not-installed",
                TargetVersion = targetManifest.Version
            };

            if (installed == null)
            {
                plan.Errors.Add($"Pack {targetManifest.PackId} is not installed.");
                return plan;
            }

            var currentManifest = _registry.LoadInstalledManifest(targetManifest.PackId);
            if (currentManifest == null)
            {
                plan.Errors.Add($"Installed manifest for {targetManifest.PackId} is missing.");
                return plan;
            }

            if (!TryParseVersion(installed.Version, out var currentVersion))
                plan.Errors.Add($"Installed pack version '{installed.Version}' is not a valid semantic version.");
            if (!TryParseVersion(targetManifest.Version, out var targetVersion))
                plan.Errors.Add($"Target pack version '{targetManifest.Version}' is not a valid semantic version.");
            if (plan.Errors.Count > 0)
                return plan;

            plan.IsDowngrade = targetVersion < currentVersion;
            if (plan.IsDowngrade && !allowDowngrade)
                plan.Errors.Add("Downgrade requires explicit approval.");

            var currentRules = BuildRuleMap(currentManifest.Rules, plan, "current installed manifest");
            var targetRules = BuildRuleMap(targetManifest.Rules, plan, "target manifest");
            plan.AddedRuleIds.AddRange(targetRules.Keys.Except(currentRules.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase));
            plan.DeprecatedRuleIds.AddRange(targetRules.Values.Where(static rule => rule.Deprecated).Select(static rule => rule.RuleId).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase));

            foreach (var removed in currentRules.Keys.Except(targetRules.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase))
            {
                plan.RemovedRuleIds.Add(removed);
                if (!currentRules[removed].Deprecated)
                    plan.Errors.Add($"Rule {removed} cannot be removed until it is first shipped as deprecated.");
            }

            plan.PreservedUserOverrideNotes.Add("rules.json explicit overrides remain authoritative across pack upgrades.");
            return plan;
        }

        public ContentPackUpgradeResult Upgrade(ContentPackManifest targetManifest, bool allowDowngrade = false, bool runBenchmark = true, string benchmarkOutputDirectory = "build-verify")
        {
            var plan = PlanUpgrade(targetManifest, allowDowngrade);
            if (plan.Errors.Count > 0)
                return new ContentPackUpgradeResult { PackId = targetManifest.PackId, Plan = plan, Errors = plan.Errors.ToList() };

            var install = Install(targetManifest, enableAfterInstall: _registry.GetEnabledPackIds().Contains(targetManifest.PackId), runBenchmark: runBenchmark, benchmarkOutputDirectory: benchmarkOutputDirectory);
            return new ContentPackUpgradeResult
            {
                PackId = targetManifest.PackId,
                Plan = plan,
                InstalledPack = install.InstalledPack,
                Warnings = plan.Warnings.ToList()
            };
        }


        private static bool TryParseVersion(string? value, out Version version)
        {
            version = new Version(0, 0, 0);
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var normalized = value.Trim().Split('-', '+')[0];
            if (!Version.TryParse(normalized, out var parsed) || parsed == null)
                return false;

            version = parsed;
            return true;
        }

        private static Dictionary<string, ContentPackRule> BuildRuleMap(IEnumerable<ContentPackRule>? rules, ContentPackUpgradePlan plan, string sourceName)
        {
            var map = new Dictionary<string, ContentPackRule>(StringComparer.OrdinalIgnoreCase);
            foreach (var group in (rules ?? Array.Empty<ContentPackRule>())
                         .Where(static rule => rule != null && !string.IsNullOrWhiteSpace(rule.RuleId))
                         .GroupBy(static rule => rule.RuleId.Trim(), StringComparer.OrdinalIgnoreCase))
            {
                var first = group.First();
                map[group.Key] = first;
                if (group.Count() > 1)
                    plan.Errors.Add($"Duplicate rule ID {group.Key} found in {sourceName}.");
            }

            if ((rules ?? Array.Empty<ContentPackRule>()).Any(static rule => rule == null || string.IsNullOrWhiteSpace(rule.RuleId)))
                plan.Errors.Add($"One or more rules in {sourceName} have a missing RuleId.");

            return map;
        }

        private static ContentPackInstallPlan BuildPlan(ContentPackManifest manifest, ContentPackValidationResult validation, bool enableAfterInstall)
        {
            var plan = new ContentPackInstallPlan
            {
                PackId = manifest.PackId,
                Version = manifest.Version,
                DryRun = true,
                EnableAfterInstall = enableAfterInstall,
                Validation = validation
            };

            plan.NewRuleIds.AddRange(manifest.Rules.Select(static rule => rule.RuleId).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase));
            plan.ProfileChanges.AddRange(manifest.Profiles.Select(profile => $"{profile.ProfileName}: {profile.DefaultMode}"));
            plan.TuningChanges.AddRange(manifest.TuningDefaults.Select(tuning => $"{tuning.RuleId}: mode={tuning.RecommendedMode}, threshold={tuning.Threshold}, window={tuning.WindowSeconds}"));
            plan.ReplaySamples.AddRange(manifest.ReplaySamples.Select(sample => sample.SampleId));
            plan.ResponseRecommendations.AddRange(manifest.ResponseRecommendations.Select(item => item.Title));
            plan.SafetyWarnings.AddRange(manifest.SafetyNotes);

            foreach (var ruleId in plan.NewRuleIds)
                plan.PlannedChanges.Add($"Register compiled content-pack rule {ruleId}.");
            foreach (var profile in plan.ProfileChanges)
                plan.PlannedChanges.Add($"Apply profile default {profile}.");
            foreach (var tuning in plan.TuningChanges)
                plan.PlannedChanges.Add($"Apply tuning default {tuning}.");
            if (enableAfterInstall)
                plan.PlannedChanges.Add("Enable pack after installation.");

            plan.Errors.AddRange(validation.Errors);
            return plan;
        }
    }
}
