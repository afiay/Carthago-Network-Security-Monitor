// SPDX-License-Identifier: MIT
// File: Engine/Rules/Tuning/RuleTuningReason.cs
namespace Carthago.Engine.Rules.Tuning
{
    public enum RuleTuningReason
    {
        LegacyCompatibility,
        HealthSignal,
        StrongPayloadSignature,
        HeuristicPayloadIndicator,
        BaselineNovelty,
        EnvironmentScopedDetection,
        IdentityContextRequired,
        CloudOrSaasContextRequired,
        IoTAssetApprovalRequired,
        OtAssetApprovalRequired,
        ContainerOrCloudContextRequired,
        DirectCredentialExposure,
        ExfiltrationIndicator,
        KnownC2OrMalwarePattern,
        ExploitProbeSignature,
        ConfidenceFloorApplied,
        BaselineLearningMode,
        MissingEnvironmentConfiguration,
        ApprovedAssetMatched,
        ResearchProfileBroadAlerting,
        ProductionNoiseGuard,
        ExplicitProfilePromotion,
        ThreatHuntingCoverage,
        PipelineLossRisk
    }
}
