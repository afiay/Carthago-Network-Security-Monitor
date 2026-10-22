// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R082_NTLMRelaySuspicionRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R082_NTLMRelaySuspicionRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R082",
            Name: "NTLM Relay Suspicion",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for NTLM Relay Suspicion. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R082.Enabled",
            EnabledByDefault: true);
    }
}
