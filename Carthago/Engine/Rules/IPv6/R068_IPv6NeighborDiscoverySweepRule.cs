// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R068_IPv6NeighborDiscoverySweepRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R068_IPv6NeighborDiscoverySweepRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R068",
            Name: "IPv6 Neighbor Discovery Sweep",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for IPv6 Neighbor Discovery Sweep. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R068.Enabled",
            EnabledByDefault: true);
    }
}
