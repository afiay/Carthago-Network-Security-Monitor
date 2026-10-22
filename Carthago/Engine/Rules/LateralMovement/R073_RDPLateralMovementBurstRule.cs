// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R073_RDPLateralMovementBurstRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R073_RDPLateralMovementBurstRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R073",
            Name: "RDP Lateral Movement Burst",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for RDP Lateral Movement Burst. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R073.Enabled",
            EnabledByDefault: true);
    }
}
