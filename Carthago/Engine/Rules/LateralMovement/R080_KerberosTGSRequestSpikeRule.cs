// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R080_KerberosTGSRequestSpikeRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R080_KerberosTGSRequestSpikeRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R080",
            Name: "Kerberos TGS Request Spike",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for Kerberos TGS Request Spike. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R080.Enabled",
            EnabledByDefault: true);
    }
}
