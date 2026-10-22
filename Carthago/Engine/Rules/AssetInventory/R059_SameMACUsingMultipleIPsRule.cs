// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R059_SameMACUsingMultipleIPsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R059_SameMACUsingMultipleIPsRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R059",
            Name: "Same MAC Using Multiple IPs",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for Same MAC Using Multiple IPs. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R059.Enabled",
            EnabledByDefault: true);
    }
}
