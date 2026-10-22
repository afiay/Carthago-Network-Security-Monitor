// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R077_RPCServiceControlPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R077_RPCServiceControlPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R077",
            Name: "RPC Service Control Pattern",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for RPC Service Control Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R077.Enabled",
            EnabledByDefault: true);
    }
}
