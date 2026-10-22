// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R067_RogueIPv6RouterAdvertisementRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R067_RogueIPv6RouterAdvertisementRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R067",
            Name: "Rogue IPv6 Router Advertisement",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for Rogue IPv6 Router Advertisement. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R067.Enabled",
            EnabledByDefault: true);
    }
}
