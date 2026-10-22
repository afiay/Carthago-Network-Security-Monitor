// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackRegistry.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Carthago.Services.Hunting;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackActivationOptions
    {
        public IEnumerable<string> ConfiguredRuleIds { get; set; } = Array.Empty<string>();
    }

    public sealed class ContentPackActivationResult
    {
        public List<IContentPackRule> ActiveRules { get; } = new();
        public List<string> SkippedConfiguredRuleIds { get; } = new();
    }

    public sealed class ContentPackRegistry
    {
        private readonly CompiledContentPackRegistry _compiledRegistry;
        private readonly ContentPackStore _store;

        public ContentPackRegistry(CompiledContentPackRegistry? compiledRegistry = null, ContentPackStore? store = null)
        {
            _compiledRegistry = compiledRegistry ?? new CompiledContentPackRegistry();
            _store = store ?? new ContentPackStore();
        }

        public IReadOnlyList<ContentPackManifest> GetAvailablePacks()
            => _compiledRegistry.GetAvailablePacks();

        public ContentPackInstallState LoadState()
            => _store.Load();

        public IReadOnlyList<InstalledContentPackState> GetInstalledPacks()
            => LoadState().InstalledPacks.OrderBy(static pack => pack.PackId, StringComparer.OrdinalIgnoreCase).ToArray();

        public IReadOnlyCollection<string> GetEnabledPackIds()
            => LoadState().InstalledPacks
                .Where(static pack => pack.Enabled)
                .Select(static pack => pack.PackId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyList<ContentPackRuleRegistration> GetAllAvailableRuleRegistrations()
        {
            var installedManifestByPackId = LoadState().InstalledPacks
                .Where(static installed => !string.IsNullOrWhiteSpace(installed.PackId))
                .Select(installed => new { installed.PackId, Manifest = _store.LoadManifest(installed.PackId) })
                .Where(static item => item.Manifest != null)
                .GroupBy(static item => item.PackId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => group.Last().Manifest!, StringComparer.OrdinalIgnoreCase);
            var sourceRules = RuleCatalog.Rules
                .Where(static rule => !string.IsNullOrWhiteSpace(rule.Descriptor.RuleId))
                .GroupBy(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.OrdinalIgnoreCase);

            return _compiledRegistry.GetAllRuleRegistrations()
                .Select(registration => OverlayInstalledManifest(registration, installedManifestByPackId, sourceRules))
                .OrderBy(static registration => registration.Rule.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public ContentPackActivationResult CreateActivation(ContentPackActivationOptions? options = null)
        {
            var result = new ContentPackActivationResult();
            var enabledPackIds = GetEnabledPackIds();
            var availableRules = GetAllAvailableRuleRegistrations();

            foreach (var registration in availableRules)
            {
                if (enabledPackIds.Contains(registration.PackId))
                {
                    if (registration.CompiledRule != null)
                        result.ActiveRules.Add(registration.CompiledRule);
                }
                else if ((options?.ConfiguredRuleIds ?? Array.Empty<string>()).Any(ruleId => string.Equals(ruleId, registration.Rule.RuleId, StringComparison.OrdinalIgnoreCase)))
                {
                    result.SkippedConfiguredRuleIds.Add(registration.Rule.RuleId);
                }
            }

            return result;
        }

        public IReadOnlyList<IContentPackRule> GetActiveRules(ContentPackActivationOptions? options = null)
            => CreateActivation(options).ActiveRules;

        public IReadOnlyList<SavedHunt> GetEnabledHunts()
        {
            var enabled = GetEnabledPackIds();
            return _compiledRegistry.Providers
                .Where(provider => enabled.Contains(provider.Manifest.PackId))
                .SelectMany(provider => provider.Manifest.HuntingQueries.Select(hunt => new SavedHunt
                {
                    HuntId = hunt.HuntId,
                    PackId = provider.Manifest.PackId,
                    Name = hunt.Name,
                    Query = new HuntQuery
                    {
                        RuleId = hunt.PrimaryRuleId,
                        MinConfidence = hunt.MinConfidence
                    }
                }))
                .OrderBy(static hunt => hunt.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public IReadOnlyList<ResponseAction> BuildRecommendations(string packId, string ruleId, string eventId, string? incidentId = null)
        {
            var enabledPackIds = GetEnabledPackIds();
            if (!enabledPackIds.Contains(packId))
                return Array.Empty<ResponseAction>();

            var provider = _compiledRegistry.FindProvider(packId);
            if (provider == null)
                return Array.Empty<ResponseAction>();

            return provider.Manifest.ResponseRecommendations
                .Where(rec => rec.AppliesToRuleIds.Count == 0 || rec.AppliesToRuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase))
                .Select(rec => new ResponseAction
                {
                    ActionType = rec.ActionType,
                    Safety = rec.Safety,
                    RequiresApproval = rec.RequiresApproval || rec.Safety == ResponseActionSafety.Destructive,
                    Reason = rec.Description,
                    SourceEventId = eventId,
                    SourceIncidentId = incidentId,
                    SourceRuleId = ruleId,
                    RollbackGuidance = string.IsNullOrWhiteSpace(rec.SafetyWarning)
                        ? "No automatic rollback was performed. Use the linked operational system for any enforcement undo."
                        : rec.SafetyWarning
                })
                .ToArray();
        }

        public RuleMode ResolvePackRuleMode(string packId, string ruleId, string? profileName, double confidenceScore, bool telemetryAvailable, EnvironmentTuningOptions? tuning = null)
        {
            var provider = _compiledRegistry.FindProvider(packId);
            if (provider == null)
                return RuleMode.Disabled;

            var profile = provider.Manifest.Profiles
                .FirstOrDefault(item => string.Equals(item.ProfileName, RuleTuningCatalog.NormalizeProfileName(profileName), StringComparison.OrdinalIgnoreCase))
                ?? provider.Manifest.Profiles.FirstOrDefault(item => string.Equals(item.ProfileName, RuleTuningCatalog.DefaultProfileName, StringComparison.OrdinalIgnoreCase));

            if (profile == null)
                return RuleMode.Shadow;

            if (!telemetryAvailable && profile.DisableWhenTelemetryMissing)
                return RuleMode.Disabled;

            if (!HasRequiredApprovedAssets(profile, tuning))
                return profile.DefaultMode == RuleMode.Alert ? RuleMode.Shadow : RuleMode.Disabled;

            var perRule = provider.Manifest.TuningDefaults.FirstOrDefault(item => string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
            var mode = perRule?.RecommendedMode ?? profile.DefaultMode;
            var confidenceFloor = perRule?.ConfidenceFloor ?? profile.ConfidenceFloorForAlert;

            if (mode == RuleMode.Alert && confidenceFloor.HasValue && confidenceScore < confidenceFloor.Value)
                return RuleMode.Shadow;

            return mode;
        }

        public ContentPackManifest? LoadInstalledManifest(string packId)
            => _store.LoadManifest(packId);

        internal ContentPackStore Store => _store;
        internal CompiledContentPackRegistry Compiled => _compiledRegistry;

        private static ContentPackRuleRegistration OverlayInstalledManifest(
            ContentPackRuleRegistration registration,
            IReadOnlyDictionary<string, ContentPackManifest> installedManifestByPackId,
            IReadOnlyDictionary<string, IDetectionRule> sourceRules)
        {
            if (!installedManifestByPackId.TryGetValue(registration.PackId, out var manifest))
                return registration;

            var installedRule = manifest.Rules.FirstOrDefault(rule =>
                string.Equals(rule.RuleId, registration.Rule.RuleId, StringComparison.OrdinalIgnoreCase));
            var coreRuleId = installedRule?.Source?.CoreRuleId;
            if (installedRule == null || string.IsNullOrWhiteSpace(coreRuleId) || !sourceRules.TryGetValue(coreRuleId, out var sourceRule))
                return registration;

            return new ContentPackRuleRegistration
            {
                PackId = manifest.PackId,
                PackVersion = manifest.Version,
                Rule = installedRule,
                CompiledRule = new CompiledContentPackRule(manifest.PackId, installedRule, sourceRule)
            };
        }

        private static bool HasRequiredApprovedAssets(ContentPackProfileDefaults profile, EnvironmentTuningOptions? tuning)
        {
            if (profile.RequiredApprovedAssets.Count == 0)
                return true;

            var approved = tuning?.Approved ?? ApprovedAssetRegistry.Current.Options.Approved;
            foreach (var required in profile.RequiredApprovedAssets)
            {
                if (required.Equals("Approved.KubernetesApiServers", StringComparison.OrdinalIgnoreCase) && approved.KubernetesApiServers.Count == 0)
                    return false;
                if (required.Equals("Approved.CiCdServers", StringComparison.OrdinalIgnoreCase) && approved.CiCdServers.Count == 0)
                    return false;
                if (required.Equals("Approved.DomainControllers", StringComparison.OrdinalIgnoreCase) && approved.DomainControllers.Count == 0)
                    return false;
                if (required.Equals("Approved.OtSegments", StringComparison.OrdinalIgnoreCase) && approved.OtSegments.Count == 0)
                    return false;
                if (required.Equals("Approved.MqttBrokers", StringComparison.OrdinalIgnoreCase) && approved.MqttBrokers.Count == 0)
                    return false;
                if (required.Equals("Approved.AdminHosts", StringComparison.OrdinalIgnoreCase) && approved.AdminHosts.Count == 0)
                    return false;
            }

            return true;
        }
    }
}
