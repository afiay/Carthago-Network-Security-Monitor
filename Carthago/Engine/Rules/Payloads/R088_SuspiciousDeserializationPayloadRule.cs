// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R088_SuspiciousDeserializationPayloadRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R088_SuspiciousDeserializationPayloadRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R088",
            Name: "Suspicious Deserialization Payload",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Suspicious Deserialization Payload. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R088.Enabled",
            EnabledByDefault: true);
    }
}
