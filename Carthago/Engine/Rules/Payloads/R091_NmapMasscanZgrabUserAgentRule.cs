// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R091_NmapMasscanZgrabUserAgentRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R091_NmapMasscanZgrabUserAgentRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R091",
            Name: "Nmap / Masscan / Zgrab User-Agent",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Nmap / Masscan / Zgrab User-Agent. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R091.Enabled",
            EnabledByDefault: true);
    }
}
