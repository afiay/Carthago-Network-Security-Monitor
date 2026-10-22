// SPDX-License-Identifier: MIT
// File: Engine/Rules/Tuning/RuleTuningClassifier.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Engine.Rules.Tuning
{
    public static class RuleTuningClassifier
    {
        private static readonly HashSet<int> StrongPayloadRules = new()
        {
            84, 85, 86, 87, 88, 89, 90, 93,
            159, 160, 161, 163, 166, 167, 170, 175, 177,
            198, 199, 200, 201, 205, 212,
            244, 245, 246, 249, 250, 253, 257,
            270, 274, 275, 276,
            294, 295, 297, 298, 299, 300,
            353, 354, 359, 360, 365, 367, 369, 374, 383, 387,
            393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411,
            414, 415, 416, 417, 422, 423, 437, 438,
            485,
            493, 494, 495, 497, 500, 503, 504, 505, 506, 507, 508,
            513, 514, 515, 516, 517, 518, 520, 521, 523
        };

        private static readonly HashSet<int> MediumPayloadRules = new()
        {
            91, 92, 139, 148, 150, 156, 162, 168, 171, 172, 173, 174, 176,
            178, 182, 189, 192, 193, 194, 195, 197,
            206, 207, 208, 217, 218, 219, 221, 222,
            243, 247, 248, 251, 252, 254, 255, 263, 264, 267, 268, 271, 272,
            281, 282, 283, 284, 286, 288, 290, 291, 292,
            301, 302, 305, 307, 309, 310, 311, 312,
            317, 318, 319, 320, 321, 322, 324, 325, 327, 328, 329, 330, 332,
            336, 337, 338, 341, 343, 344, 345, 346, 349, 351, 352,
            355, 356, 357, 361, 362, 363, 364, 366, 368, 370, 371, 372, 373, 375, 376, 378, 379, 380, 381, 382, 384, 385, 386, 388, 389, 390, 391, 392,
            404, 412,
            424, 425, 426, 427, 428, 430, 431, 432, 433, 434, 435, 436, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452,
            471, 472,
            473, 474, 475, 476, 477, 478, 480, 481, 482, 483, 484, 486, 487, 488, 489, 490, 492,
            496, 498, 499, 501, 502, 509, 510, 511, 512,
            519, 522, 524, 525, 526, 527, 528
        };

        private static readonly HashSet<int> BaselinePromotionRules = new() { 102, 103 };
        private static readonly HashSet<int> NoisyLateralRules = new() { 79, 80, 81, 82, 83 };

        public static RuleTuningDecision Classify(RuleDescriptor descriptor)
        {
            if (descriptor == null) throw new ArgumentNullException(nameof(descriptor));

            var n = RuleNumber(descriptor.RuleId);
            var tier = DetermineTier(n);
            var reasons = new List<RuleTuningReason>();
            var details = new List<string>();
            var requiredProfiles = new List<string>();
            var requiredAssets = new List<string>();
            var confidenceFloor = ConfidenceFloorFor(tier, n);
            var requiresBaseline = tier == RuleTuningTier.BaselineRequired;
            string? baselineDependency = requiresBaseline ? "BaselineStore observations and environment learning state." : null;
            var noisyByDefault = tier is RuleTuningTier.ShadowFirst or RuleTuningTier.BaselineRequired or RuleTuningTier.EnvironmentSpecific or RuleTuningTier.DisabledUntilConfigured;

            switch (tier)
            {
                case RuleTuningTier.HighFidelityAlert:
                    reasons.Add(IsExploitOrPayload(n) ? RuleTuningReason.StrongPayloadSignature : RuleTuningReason.KnownC2OrMalwarePattern);
                    details.Add("Strong exploit, secret exposure, credential theft, or malware C2 telemetry with direct evidence.");
                    break;
                case RuleTuningTier.MediumFidelityAlert:
                    reasons.Add(IsDirectCredentialLeak(n) ? RuleTuningReason.DirectCredentialExposure : RuleTuningReason.ExploitProbeSignature);
                    details.Add("Useful alerting signal, but one that still benefits from confidence gating and profile-aware defaults.");
                    break;
                case RuleTuningTier.ShadowFirst:
                    reasons.Add(RuleTuningReason.ProductionNoiseGuard);
                    details.Add("Discovery, novelty, or broad heuristic rule that should stay visible without paging by default.");
                    break;
                case RuleTuningTier.BaselineRequired:
                    reasons.Add(RuleTuningReason.BaselineNovelty);
                    details.Add("Requires enough baseline history to distinguish first-seen behavior from benign change.");
                    break;
                case RuleTuningTier.EnvironmentSpecific:
                    reasons.Add(IsOtOrIcs(n) ? RuleTuningReason.OtAssetApprovalRequired : RuleTuningReason.EnvironmentScopedDetection);
                    details.Add("Only meaningful when the profile and approved-asset inventory say the environment actually uses this protocol or workflow.");
                    break;
                case RuleTuningTier.DisabledUntilConfigured:
                    reasons.Add(RuleTuningReason.ContainerOrCloudContextRequired);
                    details.Add("Needs explicit cluster, controller, or enterprise-service configuration before production alerting is safe.");
                    break;
                case RuleTuningTier.HealthOnly:
                    reasons.Add(RuleTuningReason.HealthSignal);
                    details.Add("Represents platform health or pipeline durability rather than adversary behavior.");
                    break;
            }

            if (n is >= 1 and <= 49)
            {
                reasons.Add(RuleTuningReason.LegacyCompatibility);
                details.Add("Preserved legacy-compatible rule; defaults should honor historical semantics and only tune through thresholds, cooldowns, or profile mode.");
            }

            if (tier == RuleTuningTier.BaselineRequired && BaselinePromotionRules.Contains(n))
                details.Add("High-confidence variants can promote to alert after the environment leaves learning mode.");

            if (tier == RuleTuningTier.EnvironmentSpecific)
            {
                if (n is >= 113 and <= 119)
                {
                    requiredProfiles.AddRange(new[] { "IoTHeavy", "OTSegment" });
                    requiredAssets.Add("Approved.MqttBrokers");
                    reasons.Add(RuleTuningReason.IoTAssetApprovalRequired);
                }
                else if (n is 120 or 121 or 122 or >= 223 and <= 242 or >= 473 and <= 492)
                {
                    requiredProfiles.Add("OTSegment");
                    requiredAssets.Add("Approved.OtSegments");
                    requiredAssets.Add("Approved.ModbusControllers");
                    requiredAssets.Add("Approved.BacnetControllers");
                    reasons.Add(RuleTuningReason.OtAssetApprovalRequired);
                }
                else if (n is >= 67 and <= 72)
                {
                    requiredProfiles.AddRange(new[] { "Enterprise", "Research" });
                    details.Add("IPv6 and multicast rules depend on whether these transports are expected in the environment.");
                }
                else if (n is >= 333 and <= 352)
                {
                    requiredProfiles.Add("Enterprise");
                    requiredAssets.Add("Approved.DomainControllers");
                    reasons.Add(RuleTuningReason.IdentityContextRequired);
                }
            }

            if (tier == RuleTuningTier.DisabledUntilConfigured)
            {
                requiredProfiles.AddRange(new[] { "Enterprise", "Research", "OTSegment", "IoTHeavy" });
                if (n is >= 293 and <= 312)
                    requiredAssets.Add("Approved.KubernetesApiServers");
                if (n is >= 353 and <= 372)
                    requiredAssets.Add("Approved.CiCdServers");
            }

            return new RuleTuningDecision
            {
                RuleId = descriptor.RuleId,
                ProfileName = "Base",
                Tier = tier,
                DefaultMode = DefaultModeForTier(tier),
                EffectiveMode = DefaultModeForTier(tier),
                ConfidenceFloor = confidenceFloor,
                RequiresBaseline = requiresBaseline,
                BaselineDependency = baselineDependency,
                RequiredProfiles = requiredProfiles.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                RequiredAssetConfiguration = requiredAssets.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Reasons = reasons.Distinct().ToArray(),
                ReasonDetails = details.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                NoisyByDefault = noisyByDefault,
                ResearchOnly = false
            };
        }

        public static IReadOnlyList<RuleTuningDecision> Snapshot()
            => RuleCatalog.All.Select(Classify).OrderBy(static decision => decision.RuleId, StringComparer.OrdinalIgnoreCase).ToArray();

        private static RuleTuningTier DetermineTier(int n)
        {
            if (n is >= 1 and <= 49) return RuleTuningTier.HighFidelityAlert;
            if (n is >= 50 and <= 56) return RuleTuningTier.HealthOnly;
            if (n is >= 57 and <= 66) return RuleTuningTier.BaselineRequired;
            if (n is >= 67 and <= 72) return RuleTuningTier.EnvironmentSpecific;
            if (n is >= 73 and <= 83) return NoisyLateralRules.Contains(n) ? RuleTuningTier.ShadowFirst : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 84 and <= 93) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 94 and <= 103) return RuleTuningTier.BaselineRequired;
            if (n is >= 104 and <= 108) return RuleTuningTier.BaselineRequired;
            if (n is >= 109 and <= 112) return RuleTuningTier.ShadowFirst;
            if (n is >= 113 and <= 122) return RuleTuningTier.EnvironmentSpecific;
            if (n is >= 123 and <= 137) return n is 133 or 134 or 135 or 136 ? RuleTuningTier.MediumFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 138 and <= 152) return n is 139 or 150 ? RuleTuningTier.HighFidelityAlert : n is 141 or 145 or 152 ? RuleTuningTier.BaselineRequired : RuleTuningTier.ShadowFirst;
            if (n is >= 153 and <= 177) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 178 and <= 197) return n is 182 or 189 or 195 or 197 ? RuleTuningTier.MediumFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 198 and <= 222) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : n is >= 202 and <= 216 ? RuleTuningTier.ShadowFirst : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 223 and <= 242) return RuleTuningTier.EnvironmentSpecific;
            if (n is >= 243 and <= 257) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 258 and <= 272) return n is 264 or 270 or 271 ? RuleTuningTier.MediumFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 273 and <= 292) return n is 274 or 275 or 276 or 282 or 290 or 291 or 292 ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 293 and <= 312) return RuleTuningTier.DisabledUntilConfigured;
            if (n is >= 313 and <= 332) return n is 316 or 322 or 324 or 327 or 328 or 332 ? RuleTuningTier.MediumFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 333 and <= 352) return RuleTuningTier.EnvironmentSpecific;
            if (n is >= 353 and <= 372) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.DisabledUntilConfigured;
            if (n is >= 373 and <= 392) return n is 379 or 380 or 384 ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 393 and <= 412) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 413 and <= 452) return n is 414 or 415 or 416 or 417 or 422 or 423 or 437 or 438 ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 453 and <= 472) return n is 471 or 472 ? RuleTuningTier.MediumFidelityAlert : RuleTuningTier.ShadowFirst;
            if (n is >= 473 and <= 492) return n is 485 ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.EnvironmentSpecific;
            if (n is >= 493 and <= 512) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 513 and <= 528) return StrongPayloadRules.Contains(n) ? RuleTuningTier.HighFidelityAlert : RuleTuningTier.MediumFidelityAlert;
            if (n is >= 529 and <= 544) return RuleTuningTier.HealthOnly;
            return RuleTuningTier.ShadowFirst;
        }

        private static double? ConfidenceFloorFor(RuleTuningTier tier, int ruleNumber)
            => tier switch
            {
                RuleTuningTier.HighFidelityAlert => 0.75,
                RuleTuningTier.MediumFidelityAlert => 0.65,
                RuleTuningTier.BaselineRequired => BaselinePromotionRules.Contains(ruleNumber) ? 0.70 : 0.70,
                RuleTuningTier.HealthOnly => 0.60,
                _ => null
            };

        private static RuleMode DefaultModeForTier(RuleTuningTier tier)
            => tier switch
            {
                RuleTuningTier.HighFidelityAlert => RuleMode.Alert,
                RuleTuningTier.MediumFidelityAlert => RuleMode.Alert,
                RuleTuningTier.ShadowFirst => RuleMode.Shadow,
                RuleTuningTier.BaselineRequired => RuleMode.Shadow,
                RuleTuningTier.EnvironmentSpecific => RuleMode.Shadow,
                RuleTuningTier.DisabledUntilConfigured => RuleMode.Disabled,
                RuleTuningTier.HealthOnly => RuleMode.Alert,
                _ => RuleMode.Shadow
            };

        internal static int RuleNumber(string? ruleId)
            => int.TryParse((ruleId ?? string.Empty).Trim().TrimStart('R', 'r'), out var n) ? n : 0;

        internal static bool IsExploitOrPayload(int n) => StrongPayloadRules.Contains(n);
        internal static bool IsDirectCredentialLeak(int n) => n is 14 or 133 or 134 or 135 or 136 or 205 or 353 or 354 or 359 or 360 or 365 or 367 or 369 or 374 or 383;
        internal static bool IsOtOrIcs(int n) => n is 120 or 121 or 122 || (n >= 223 && n <= 242) || (n >= 473 && n <= 492);
    }
}
