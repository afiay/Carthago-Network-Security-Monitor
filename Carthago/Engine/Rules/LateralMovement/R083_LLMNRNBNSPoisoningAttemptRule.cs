// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R083_LLMNRNBNSPoisoningAttemptRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R083_LLMNRNBNSPoisoningAttemptRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R083",
            Name: "LLMNR / NBNS Poisoning Attempt",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for LLMNR / NBNS Poisoning Attempt. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R083.Enabled",
            EnabledByDefault: true);
    }
}
