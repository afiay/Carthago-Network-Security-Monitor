// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R063_WorkstationActingLikeServerRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R063_WorkstationActingLikeServerRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R063",
            Name: "Workstation Acting Like Server",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for Workstation Acting Like Server. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R063.Enabled",
            EnabledByDefault: true);
    }
}
