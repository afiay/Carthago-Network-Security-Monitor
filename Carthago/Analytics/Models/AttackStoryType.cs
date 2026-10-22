// SPDX-License-Identifier: MIT
// File: Analytics/Models/AttackStoryType.cs
namespace Carthago.Analytics.Models
{
    public enum AttackStoryType
    {
        None,
        ReconnaissanceToLateralMovement,
        ExploitToCallback,
        LateralMovementToExfiltration,
        DnsC2Suspicion,
        IoTCompromiseSuspicion,
        OTSegmentViolation,
        CloudExfiltrationSuspicion,
        IdentityCompromiseSuspicion,
        KubernetesCompromiseSuspicion,
        MalwareC2Suspicion,
        NetworkApplianceExposureIncident,
        DatabaseExposureIncident,
        DevOpsSupplyChainSuspicion,
        DataLossStagingSuspicion,
        EvasionTunnelSuspicion,
        DetectionPipelineHealthIncident
    }
}
