// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R062_NewServiceOpenedOnInternalHostRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R062_NewServiceOpenedOnInternalHostRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R062",
            Name: "New Service Opened on Internal Host",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for New Service Opened on Internal Host. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R062.Enabled",
            EnabledByDefault: true);
    }
}
