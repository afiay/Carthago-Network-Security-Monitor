// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R078_PsExecLikeNetworkBehaviorRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R078_PsExecLikeNetworkBehaviorRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R078",
            Name: "PsExec-Like Network Behavior",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for PsExec-Like Network Behavior. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R078.Enabled",
            EnabledByDefault: true);
    }
}
