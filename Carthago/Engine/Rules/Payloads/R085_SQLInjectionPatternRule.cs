// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R085_SQLInjectionPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R085_SQLInjectionPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R085",
            Name: "SQL Injection Pattern",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for SQL Injection Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R085.Enabled",
            EnabledByDefault: true);
    }
}
