// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R089_CommandInjectionPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R089_CommandInjectionPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R089",
            Name: "Command Injection Pattern",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Command Injection Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R089.Enabled",
            EnabledByDefault: true);
    }
}
