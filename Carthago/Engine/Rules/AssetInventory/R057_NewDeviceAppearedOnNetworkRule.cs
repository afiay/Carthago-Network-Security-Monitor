// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R057_NewDeviceAppearedOnNetworkRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R057_NewDeviceAppearedOnNetworkRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R057",
            Name: "New Device Appeared on Network",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for New Device Appeared on Network. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R057.Enabled",
            EnabledByDefault: true);
    }
}
