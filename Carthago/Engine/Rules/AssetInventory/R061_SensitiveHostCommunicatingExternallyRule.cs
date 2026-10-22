// SPDX-License-Identifier: MIT
// File: Engine/Rules/AssetInventory/R061_SensitiveHostCommunicatingExternallyRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.AssetInventory
{
    public sealed class R061_SensitiveHostCommunicatingExternallyRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R061",
            Name: "Sensitive Host Communicating Externally",
            Category: "AssetInventory",
            Description: "Concrete telemetry-driven rule for Sensitive Host Communicating Externally. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R061.Enabled",
            EnabledByDefault: true);
    }
}
