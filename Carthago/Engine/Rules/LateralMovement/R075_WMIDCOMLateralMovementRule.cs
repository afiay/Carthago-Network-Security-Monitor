// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R075_WMIDCOMLateralMovementRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R075_WMIDCOMLateralMovementRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R075",
            Name: "WMI / DCOM Lateral Movement",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for WMI / DCOM Lateral Movement. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R075.Enabled",
            EnabledByDefault: true);
    }
}
