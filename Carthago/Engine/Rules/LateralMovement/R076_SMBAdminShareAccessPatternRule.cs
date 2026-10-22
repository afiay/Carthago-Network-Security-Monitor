// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R076_SMBAdminShareAccessPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R076_SMBAdminShareAccessPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R076",
            Name: "SMB Admin Share Access Pattern",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for SMB Admin Share Access Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R076.Enabled",
            EnabledByDefault: true);
    }
}
