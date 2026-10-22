// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R065_FirstTimeASNForHostRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R065_FirstTimeASNForHostRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R065",
            Name: "First-Time ASN for Host",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for First-Time ASN for Host. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R065.Enabled",
            EnabledByDefault: true);
    }
}
