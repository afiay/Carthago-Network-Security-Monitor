// SPDX-License-Identifier: MIT
// File: Engine/Rules/Tuning/RuleTuningCatalog.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Tuning
{
    public static class RuleTuningCatalog
    {
        public const string DefaultProfileName = "SmallBusiness";

        public static IReadOnlyList<RuleTuningProfile> Profiles { get; } = new[]
        {
            new RuleTuningProfile("HomeLab", "Low-noise production profile for personal labs.", BroadAlerting: false, NoisyRuleWarningsEnabled: true),
            new RuleTuningProfile("SmallBusiness", "Balanced production profile for smaller teams and mixed user workloads.", BroadAlerting: false, NoisyRuleWarningsEnabled: true),
            new RuleTuningProfile("Enterprise", "Enterprise production profile with stronger identity, cloud, and lateral-movement coverage.", BroadAlerting: true, NoisyRuleWarningsEnabled: true),
            new RuleTuningProfile("IoTHeavy", "Production profile for IoT-heavy networks with approved broker and camera inventories.", BroadAlerting: false, NoisyRuleWarningsEnabled: true),
            new RuleTuningProfile("OTSegment", "Production profile for OT segments with approved controllers and segment boundaries.", BroadAlerting: false, NoisyRuleWarningsEnabled: true),
            new RuleTuningProfile("Research", "Broad alerting profile for replay validation, threat hunting, and content tuning.", BroadAlerting: true, NoisyRuleWarningsEnabled: true, ResearchOnly: true)
        };

        private static readonly Lazy<IReadOnlyDictionary<string, RuleTuningDecision>> BaseDecisions = new(() =>
            RuleCatalog.All
                .Select(RuleTuningClassifier.Classify)
                .ToDictionary(static decision => decision.RuleId, StringComparer.OrdinalIgnoreCase));

        public static string NormalizeProfileName(string? profileName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return DefaultProfileName;

            var match = Profiles.FirstOrDefault(profile => string.Equals(profile.Name, profileName, StringComparison.OrdinalIgnoreCase));
            return match?.Name ?? DefaultProfileName;
        }

        public static bool IsKnownProfile(string? profileName)
            => Profiles.Any(profile => string.Equals(profile.Name, profileName, StringComparison.OrdinalIgnoreCase));

        public static RuleTuningProfile GetProfile(string? profileName)
            => Profiles.First(profile => string.Equals(profile.Name, NormalizeProfileName(profileName), StringComparison.OrdinalIgnoreCase));

        public static RuleTuningDecision GetBaseDecision(string ruleId)
        {
            if (!BaseDecisions.Value.TryGetValue(ruleId, out var decision))
                throw new KeyNotFoundException($"Unknown rule ID {ruleId}.");
            return decision;
        }

        public static RuleTuningDecision Resolve(string? profileName, RuleDescriptor descriptor, DetectionEvent? evt = null, TrafficRecord? record = null, ApprovedAssetRegistry? approvedAssets = null, bool baselineLearningMode = false, double? effectiveConfidenceScore = null)
        {
            var profile = GetProfile(profileName);
            var baseDecision = GetBaseDecision(descriptor.RuleId);
            var n = RuleTuningClassifier.RuleNumber(descriptor.RuleId);
            var defaultMode = ResolveProfileMode(profile.Name, descriptor);
            var effectiveMode = defaultMode;
            var reasons = baseDecision.Reasons.ToList();
            var details = baseDecision.ReasonDetails.ToList();
            var environment = approvedAssets ?? ApprovedAssetRegistry.Current;

            if (baseDecision.RequiresBaseline && baselineLearningMode && effectiveMode == RuleMode.Alert)
            {
                effectiveMode = RuleMode.Shadow;
                reasons.Add(RuleTuningReason.BaselineLearningMode);
                details.Add("Baseline learning mode is active, so this baseline-dependent rule remains in Shadow until the environment has enough observations.");
            }

            if (!profile.ResearchOnly && (baseDecision.Tier is RuleTuningTier.EnvironmentSpecific or RuleTuningTier.DisabledUntilConfigured))
            {
                if (!HasRequiredEnvironmentConfiguration(baseDecision, environment, profile.Name, n))
                {
                    var constrainedMode = baseDecision.Tier == RuleTuningTier.DisabledUntilConfigured ? RuleMode.Disabled : RuleMode.Shadow;
                    effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, constrainedMode);
                    reasons.Add(RuleTuningReason.MissingEnvironmentConfiguration);
                    details.Add("Required profile scope or approved asset configuration is missing, so the rule stays non-paging by default.");
                }
            }

            var confidence = effectiveConfidenceScore ?? evt?.ConfidenceScore ?? 0.0;
            if (effectiveMode == RuleMode.Alert && baseDecision.ConfidenceFloor.HasValue && confidence < baseDecision.ConfidenceFloor.Value)
            {
                effectiveMode = RuleMode.Shadow;
                reasons.Add(RuleTuningReason.ConfidenceFloorApplied);
                details.Add($"Confidence {confidence:F2} is below the {baseDecision.ConfidenceFloor.Value:F2} floor for {baseDecision.Tier}.");
            }

            if (evt != null && record != null)
            {
                var approvedDecision = environment.Evaluate(descriptor.RuleId, evt, record, profile.Name);
                if (approvedDecision != null && approvedDecision.Disposition == ApprovedAssetDisposition.Shadow)
                {
                    effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, RuleMode.Shadow);
                    reasons.Add(RuleTuningReason.ApprovedAssetMatched);
                    details.Add($"{approvedDecision.Reason} ({approvedDecision.ConfigKey}: {approvedDecision.MatchedValue})");
                }
            }

            if (profile.ResearchOnly)
            {
                reasons.Add(RuleTuningReason.ResearchProfileBroadAlerting);
                details.Add("Research profile intentionally keeps broad alert coverage enabled for validation and tuning.");
            }

            return baseDecision with
            {
                ProfileName = profile.Name,
                DefaultMode = defaultMode,
                EffectiveMode = effectiveMode,
                Reasons = reasons.Distinct().ToArray(),
                ReasonDetails = details.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                ResearchOnly = profile.ResearchOnly
            };
        }

        public static RuleMode ResolveProfileMode(string? profileName, RuleDescriptor descriptor)
        {
            var profile = NormalizeProfileName(profileName);
            var baseDecision = GetBaseDecision(descriptor.RuleId);
            var n = RuleTuningClassifier.RuleNumber(descriptor.RuleId);

            if (profile == "Research")
                return RuleMode.Alert;

            var profileMode = profile switch
            {
                "HomeLab" => ResolveHomeLabMode(baseDecision, n),
                "SmallBusiness" => ResolveSmallBusinessMode(baseDecision, n),
                "Enterprise" => ResolveEnterpriseMode(baseDecision, n),
                "IoTHeavy" => ResolveIoTHeavyMode(baseDecision, n),
                "OTSegment" => ResolveOtSegmentMode(baseDecision, n),
                _ => ResolveSmallBusinessMode(baseDecision, n)
            };

            var precisionMode = RulePrecisionCatalog.ToRuleMode(RulePrecisionCatalog.GetProfile(descriptor).DefaultMode);
            return RulePrecisionCatalog.MostRestrictive(profileMode, precisionMode);
        }

        private static RuleMode ResolveHomeLabMode(RuleTuningDecision decision, int n)
        {
            if (n is >= 1 and <= 49) return RuleMode.Alert;
            if (n == 102) return RuleMode.Alert;
            if (n is >= 84 and <= 93 && decision.Tier != RuleTuningTier.ShadowFirst) return RuleMode.Alert;
            if (n is >= 223 and <= 242 or >= 293 and <= 392 or >= 473 and <= 492) return RuleMode.Disabled;
            if (n is >= 113 and <= 122 or >= 333 and <= 352) return RuleMode.Disabled;
            return decision.Tier switch
            {
                RuleTuningTier.HighFidelityAlert => RuleMode.Shadow,
                RuleTuningTier.MediumFidelityAlert => RuleMode.Shadow,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Disabled,
                _ => RuleMode.Shadow
            };
        }

        private static RuleMode ResolveSmallBusinessMode(RuleTuningDecision decision, int n)
        {
            if (n is >= 1 and <= 49) return RuleMode.Alert;
            if (n is >= 84 and <= 93) return RuleMode.Alert;
            if (n is 133 or 134 or 135 or 136 or 198 or 199 or 200 or 201 or 244 or 245 or 246 or 249 or 250 or 253 or 257 or 393 or 394 or 395 or 396 or 397 or 398 or 399 or 400 or 401 or 402 or 403 or 404 or 405 or 406 or 407 or 408 or 409 or 410 or 411 or 516)
                return RuleMode.Alert;
            if (decision.Tier == RuleTuningTier.BaselineRequired) return RuleMode.Shadow;
            if (n is >= 223 and <= 242 or >= 473 and <= 492) return RuleMode.Shadow;
            if (n is >= 273 and <= 392 or >= 313 and <= 332) return RuleMode.Shadow;
            return decision.Tier switch
            {
                RuleTuningTier.HighFidelityAlert => RuleMode.Alert,
                RuleTuningTier.MediumFidelityAlert => RuleMode.Shadow,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Disabled,
                _ => RuleMode.Shadow
            };
        }

        private static RuleMode ResolveEnterpriseMode(RuleTuningDecision decision, int n)
        {
            if (n is >= 1 and <= 49) return RuleMode.Alert;
            if (n is >= 73 and <= 83 or >= 123 and <= 152 or >= 198 and <= 222 or >= 243 and <= 257 or >= 273 and <= 392 or >= 393 and <= 452 or >= 493 and <= 528)
            {
                return decision.Tier switch
                {
                    RuleTuningTier.BaselineRequired => RuleMode.Shadow,
                    RuleTuningTier.ShadowFirst => RuleMode.Shadow,
                    RuleTuningTier.EnvironmentSpecific => RuleMode.Shadow,
                    RuleTuningTier.DisabledUntilConfigured => RuleMode.Shadow,
                    _ => RuleMode.Alert
                };
            }

            if (n is >= 223 and <= 242 or >= 473 and <= 492) return RuleMode.Shadow;
            return decision.Tier switch
            {
                RuleTuningTier.HighFidelityAlert => RuleMode.Alert,
                RuleTuningTier.MediumFidelityAlert => RuleMode.Alert,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                RuleTuningTier.BaselineRequired => RuleMode.Shadow,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Shadow,
                _ => RuleMode.Shadow
            };
        }

        private static RuleMode ResolveIoTHeavyMode(RuleTuningDecision decision, int n)
        {
            if (n is >= 1 and <= 49) return RuleMode.Alert;
            if (n is >= 113 and <= 119) return RuleMode.Alert;
            if (n is >= 120 and <= 122 or >= 223 and <= 242 or >= 473 and <= 492) return RuleMode.Disabled;
            if (n is >= 293 and <= 392 || n is >= 333 and <= 352) return RuleMode.Shadow;
            return decision.Tier switch
            {
                RuleTuningTier.HighFidelityAlert => n is 393 or 394 or 395 or 396 or 397 or 398 or 399 or 400 or 401 or 402 or 403 or 404 or 405 or 406 or 407 or 408 or 409 or 410 or 411 or 516 ? RuleMode.Alert : RuleMode.Shadow,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Disabled,
                _ => RuleMode.Shadow
            };
        }

        private static RuleMode ResolveOtSegmentMode(RuleTuningDecision decision, int n)
        {
            if (n is >= 1 and <= 49) return RuleMode.Alert;
            if (n is >= 120 and <= 122 or >= 223 and <= 242 or >= 473 and <= 492) return RuleMode.Alert;
            if (n is >= 104 and <= 112 or >= 123 and <= 222 or >= 293 and <= 392) return RuleMode.Shadow;
            return decision.Tier switch
            {
                RuleTuningTier.HighFidelityAlert => RuleMode.Alert,
                RuleTuningTier.MediumFidelityAlert => RuleMode.Shadow,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Shadow,
                _ => RuleMode.Shadow
            };
        }

        private static bool HasRequiredEnvironmentConfiguration(RuleTuningDecision decision, ApprovedAssetRegistry approvedAssets, string profileName, int n)
        {
            if (decision.Tier == RuleTuningTier.EnvironmentSpecific)
            {
                if (n is >= 113 and <= 119)
                    return string.Equals(profileName, "IoTHeavy", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(profileName, "OTSegment", StringComparison.OrdinalIgnoreCase);

                if (n is >= 120 and <= 122 or >= 223 and <= 242 or >= 473 and <= 492)
                {
                    if (!string.Equals(profileName, "OTSegment", StringComparison.OrdinalIgnoreCase))
                        return false;

                    return approvedAssets.HasApprovedOtSegments || approvedAssets.HasAnyOtControllerConfiguration;
                }

                if (n is >= 333 and <= 352)
                    return string.Equals(profileName, "Enterprise", StringComparison.OrdinalIgnoreCase)
                        && approvedAssets.Options.Approved.DomainControllers.Count > 0;
            }

            if (decision.Tier == RuleTuningTier.DisabledUntilConfigured)
            {
                if (n is >= 293 and <= 312)
                    return approvedAssets.Options.Approved.KubernetesApiServers.Count > 0;
                if (n is >= 353 and <= 372)
                    return approvedAssets.Options.Approved.CiCdServers.Count > 0;
            }

            return true;
        }
    }
}
