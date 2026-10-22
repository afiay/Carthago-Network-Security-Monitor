// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R084_Log4ShellJNDIInjectionPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R084_Log4ShellJNDIInjectionPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R084",
            Name: "Log4Shell / JNDI Injection Pattern",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Log4Shell / JNDI Injection Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R084.Enabled",
            EnabledByDefault: true);
    }
}
