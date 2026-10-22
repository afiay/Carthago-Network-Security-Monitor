// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R071_IPv6TrafficOnIPv4OnlyNetworkRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R071_IPv6TrafficOnIPv4OnlyNetworkRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R071",
            Name: "IPv6 Traffic on IPv4-Only Network",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for IPv6 Traffic on IPv4-Only Network. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R071.Enabled",
            EnabledByDefault: true);
    }
}
