// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R087_WebshellUploadPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R087_WebshellUploadPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R087",
            Name: "Webshell Upload Pattern",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Webshell Upload Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R087.Enabled",
            EnabledByDefault: true);
    }
}
