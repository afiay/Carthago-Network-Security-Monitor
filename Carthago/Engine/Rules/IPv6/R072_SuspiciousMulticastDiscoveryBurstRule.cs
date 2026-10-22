// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R072_SuspiciousMulticastDiscoveryBurstRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R072_SuspiciousMulticastDiscoveryBurstRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R072",
            Name: "Suspicious Multicast Discovery Burst",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for Suspicious Multicast Discovery Burst. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R072.Enabled",
            EnabledByDefault: true);
    }
}
