// SPDX-License-Identifier: MIT
// File: Engine/Rules/IPv6/R070_Teredo6to4ISATAPTunnelUseRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.IPv6
{
    public sealed class R070_Teredo6to4ISATAPTunnelUseRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R070",
            Name: "Teredo / 6to4 / ISATAP Tunnel Use",
            Category: "IPv6",
            Description: "Concrete telemetry-driven rule for Teredo / 6to4 / ISATAP Tunnel Use. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R070.Enabled",
            EnabledByDefault: true);
    }
}
