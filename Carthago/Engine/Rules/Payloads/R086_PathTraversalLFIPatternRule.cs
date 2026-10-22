// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R086_PathTraversalLFIPatternRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R086_PathTraversalLFIPatternRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R086",
            Name: "Path Traversal / LFI Pattern",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Path Traversal / LFI Pattern. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R086.Enabled",
            EnabledByDefault: true);
    }
}
