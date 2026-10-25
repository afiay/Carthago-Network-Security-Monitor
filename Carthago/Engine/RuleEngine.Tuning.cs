// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Tuning.cs
using Carthago.Engine.ContentPacks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.Baseline;
using Carthago.Services.Diagnostics;
using Carthago.Services.EnvironmentTuning;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static RuleTuningDecision ResolveRuntimeTuningDecision(IDetectionRule rule, DetectionEvent evt, TrafficRecord record, RuleMode configuredMode)
        {
            if (rule is IContentPackRule contentPackRule)
                return ResolveContentPackTuningDecision(contentPackRule, evt, record, configuredMode);

            var descriptor = rule.Descriptor;
            var approvedAssets = ApprovedAssetRegistry.Current;
            var baseline = BaselineStore.Current;
            var readiness = baseline.Readiness;
            var decision = RuleTuningCatalog.Resolve(
                _cfg.Profile,
                descriptor,
                evt,
                record,
                approvedAssets,
                baselineLearningMode: baseline.IsLearningMode,
                effectiveConfidenceScore: evt.ConfidenceScore,
                baselineReady: readiness.IsReady);

            var baselinePromotion = decision.RequiresBaseline && readiness.IsReady
                && decision.EffectiveMode == RuleMode.Alert && configuredMode == RuleMode.Shadow
                && !TryGetRuleModeOverride(descriptor.RuleId).HasValue;
            var precisionConfiguredMode = baselinePromotion ? RuleMode.Alert : configuredMode;
            var effectiveMode = precisionConfiguredMode switch
            {
                RuleMode.Disabled => RuleMode.Disabled,
                RuleMode.Shadow => RuleMode.Shadow,
                _ => decision.EffectiveMode
            };

            var precisionDecision = RulePrecisionRuntimeEvaluator.Evaluate(
                descriptor,
                evt,
                record,
                precisionConfiguredMode,
                _cfg.Profile);

            effectiveMode = RulePrecisionCatalog.MostRestrictive(effectiveMode, precisionDecision.EffectiveMode);

            var reasonDetails = decision.ReasonDetails
                .Concat(precisionDecision.Reasons.Select(static reason => "Precision: " + reason))
                .Concat(decision.RequiresBaseline ? new[]
                {
                    $"Baseline readiness: {(readiness.IsReady ? "ready" : "not ready")}; " +
                    $"observations={readiness.ObservationCount}; distinct={readiness.DistinctKeys}; " +
                    $"spanHours={readiness.ObservationSpan.TotalHours:F1}; " +
                    $"blockers={string.Join(", ", readiness.Blockers)}"
                } : Array.Empty<string>())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return decision with
            {
                DefaultMode = configuredMode,
                EffectiveMode = effectiveMode,
                ReasonDetails = reasonDetails
            };
        }

        private static RuleTuningDecision ResolveContentPackTuningDecision(IContentPackRule rule, DetectionEvent evt, TrafficRecord record, RuleMode configuredMode)
        {
            var profileName = RuleTuningCatalog.NormalizeProfileName(_cfg.Profile);
            var approvedAssets = ApprovedAssetRegistry.Current.Options;
            var manifest = _contentPackRegistry.LoadInstalledManifest(rule.PackId)
                ?? _contentPackRegistry.GetAvailablePacks().FirstOrDefault(pack => string.Equals(pack.PackId, rule.PackId, StringComparison.OrdinalIgnoreCase));
            var profile = manifest?.Profiles.FirstOrDefault(item => string.Equals(item.ProfileName, profileName, StringComparison.OrdinalIgnoreCase))
                ?? manifest?.Profiles.FirstOrDefault(item => string.Equals(item.ProfileName, RuleTuningCatalog.DefaultProfileName, StringComparison.OrdinalIgnoreCase));
            var perRule = manifest?.TuningDefaults.FirstOrDefault(item => string.Equals(item.RuleId, rule.Descriptor.RuleId, StringComparison.OrdinalIgnoreCase));
            var telemetry = RuleTelemetryValidator.Validate(rule, record);
            var effectiveMode = ResolveContentPackConfiguredMode(rule, record, evt.ConfidenceScore);
            var reasons = new List<RuleTuningReason> { RuleTuningReason.EnvironmentScopedDetection };
            var details = new List<string> { $"Content pack {rule.PackId} governs {rule.Descriptor.RuleId}." };

            if (!telemetry.CanRunSafely && (profile?.DisableWhenTelemetryMissing ?? true))
            {
                reasons.Add(RuleTuningReason.CloudOrSaasContextRequired);
                details.Add("Required telemetry is missing, so the pack rule remains non-paging.");
            }

            if (configuredMode == RuleMode.Alert && effectiveMode == RuleMode.Shadow)
            {
                reasons.Add(RuleTuningReason.ConfidenceFloorApplied);
                details.Add("Pack confidence floor or safety defaults reduced this detection to Shadow.");
            }

            if (effectiveMode == RuleMode.Disabled)
            {
                reasons.Add(RuleTuningReason.MissingEnvironmentConfiguration);
                details.Add("Pack profile requirements or approved assets are not satisfied.");
            }

            if (string.Equals(profileName, "Research", StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add(RuleTuningReason.ResearchProfileBroadAlerting);
                details.Add("Research profile keeps content-pack coverage broad for validation.");
            }

            var tier = profile?.RequiredApprovedAssets.Count > 0
                ? RuleTuningTier.EnvironmentSpecific
                : RuleTuningTier.ShadowFirst;

            return new RuleTuningDecision
            {
                RuleId = rule.Descriptor.RuleId,
                ProfileName = profileName,
                Tier = tier,
                DefaultMode = configuredMode,
                EffectiveMode = effectiveMode,
                ConfidenceFloor = perRule?.ConfidenceFloor ?? profile?.ConfidenceFloorForAlert,
                RequiresBaseline = false,
                BaselineDependency = null,
                RequiredProfiles = profile == null ? Array.Empty<string>() : new[] { profile.ProfileName },
                RequiredAssetConfiguration = profile?.RequiredApprovedAssets?.ToArray() ?? Array.Empty<string>(),
                Reasons = reasons.Distinct().ToArray(),
                ReasonDetails = details.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                NoisyByDefault = configuredMode == RuleMode.Alert,
                ResearchOnly = string.Equals(profileName, "Research", StringComparison.OrdinalIgnoreCase)
            };
        }

        private static void ApplyTuningDecisionToEvent(DetectionEvent evt, RuleTuningDecision decision)
        {
            if (evt == null)
                return;

            EvidenceBuilder.AppendEvidence(evt, "tuning.profile", decision.ProfileName, "rule-tuning");
            EvidenceBuilder.AppendEvidence(evt, "tuning.tier", decision.Tier.ToString(), "rule-tuning");
            EvidenceBuilder.AppendEvidence(evt, "tuning.defaultMode", decision.DefaultMode.ToString(), "rule-tuning");
            EvidenceBuilder.AppendEvidence(evt, "tuning.effectiveMode", decision.EffectiveMode.ToString(), "rule-tuning");
            if (decision.ConfidenceFloor.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "tuning.confidenceFloor", decision.ConfidenceFloor.Value.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture), "rule-tuning");

            foreach (var reason in decision.ReasonDetails)
                EvidenceBuilder.AppendEvidence(evt, "tuning.reason", reason, "rule-tuning");

            RuleRuntimeTelemetryStore.RecordTuningDecision(
                evt.RuleId,
                evt.TimestampUtc == default ? System.DateTime.UtcNow : evt.TimestampUtc,
                $"{decision.ProfileName}:{decision.Tier}:{decision.EffectiveMode}");

            evt.SuppressionStatus = decision.EffectiveMode switch
            {
                RuleMode.Alert => evt.SuppressionStatus,
                RuleMode.Shadow => DetectionSuppressionStatus.Shadowed,
                RuleMode.Disabled => DetectionSuppressionStatus.Suppressed,
                _ => evt.SuppressionStatus
            };
        }
    }
}
