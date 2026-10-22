// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R090_ReverseShellPayloadIndicatorRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R090_ReverseShellPayloadIndicatorRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R090",
            Name: "Reverse Shell Payload Indicator",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Reverse Shell Payload Indicator. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R090.Enabled",
            EnabledByDefault: true);
    }
}
