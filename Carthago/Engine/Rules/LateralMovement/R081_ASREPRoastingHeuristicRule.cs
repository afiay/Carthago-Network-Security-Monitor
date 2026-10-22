// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R081_ASREPRoastingHeuristicRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R081_ASREPRoastingHeuristicRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R081",
            Name: "AS-REP Roasting Heuristic",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for AS-REP Roasting Heuristic. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R081.Enabled",
            EnabledByDefault: true);
    }
}
