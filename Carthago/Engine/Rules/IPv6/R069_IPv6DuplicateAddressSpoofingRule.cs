// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R069_IPv6DuplicateAddressSpoofingRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R069_IPv6DuplicateAddressSpoofingRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R069",
            Name: "IPv6 Duplicate Address / Spoofing",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for IPv6 Duplicate Address / Spoofing. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R069.Enabled",
            EnabledByDefault: true);
    }
}
