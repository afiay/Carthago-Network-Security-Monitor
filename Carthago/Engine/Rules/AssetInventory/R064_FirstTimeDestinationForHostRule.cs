// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R064_FirstTimeDestinationForHostRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R064_FirstTimeDestinationForHostRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R064",
            Name: "First-Time Destination for Host",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for First-Time Destination for Host. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R064.Enabled",
            EnabledByDefault: true);
    }
}
