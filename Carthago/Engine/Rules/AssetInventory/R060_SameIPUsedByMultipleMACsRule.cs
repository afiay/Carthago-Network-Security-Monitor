// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R060_SameIPUsedByMultipleMACsRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R060_SameIPUsedByMultipleMACsRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R060",
            Name: "Same IP Used by Multiple MACs",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for Same IP Used by Multiple MACs. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R060.Enabled",
            EnabledByDefault: true);
    }
}
