// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R058_NewMACVendorSeenRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R058_NewMACVendorSeenRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R058",
            Name: "New MAC Vendor Seen",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for New MAC Vendor Seen. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R058.Enabled",
            EnabledByDefault: true);
    }
}
