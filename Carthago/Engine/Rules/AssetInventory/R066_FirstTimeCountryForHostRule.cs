// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R066_FirstTimeCountryForHostRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R066_FirstTimeCountryForHostRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R066",
            Name: "First-Time Country for Host",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for First-Time Country for Host. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R066.Enabled",
            EnabledByDefault: true);
    }
}
