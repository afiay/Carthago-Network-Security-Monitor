// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R535_TelemetryFieldCoverageDropRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R535_TelemetryFieldCoverageDropRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R535", "Telemetry Field Coverage Drop", "PlatformHealthAdvanced",
            "Detects explicit field-coverage degradation from telemetry health checks, requiring coverage/drop/missing-field semantics.",
            SeverityLevel.High, "Rules.R535.Enabled", true);

        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile("R535", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert,
            new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload }, new[] { "platform_health_event", "field_name", "coverage_drop_signal" },
            new[] { "field.name", "matched_conditions" },
            new[] { "Telemetry health must explicitly report field coverage drop or missing required fields.", "The event should include a field, parser, or telemetry family." },
            new[] { "Do not alert on a single record missing optional enrichment.", "Do not alert on protocol types where the field is not expected." },
            84, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(20), "field",
            new[] { "Parser upgrades and capture-source changes can temporarily change field coverage." },
            new[] { "Mode", "CooldownSeconds", "ExpectedFieldCoveragePercent" },
            new[] { "positive field coverage drop health event", "negative single packet missing optional field" });

        public R535_TelemetryFieldCoverageDropRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            if (!IsPlatformHealthRecord(record) || !ContainsAny(text, "field coverage", "telemetry coverage", "missing field", "field missing", "coverage drop")) return NoMatch();
            if (!ContainsAny(text, "drop", "degraded", "below", "missing", "regression", "unexpected", "required")) return NoMatch();
            var field = MetricKey(record);
            var evidence = new List<DetectionEvidenceItem> { new("field.name", field, "telemetry"), new("matched_conditions", "platform_health,telemetry_field_coverage,drop", "rule") };
            evidence.AddRange(AnalystContext("Telemetry health reported that a required field family degraded or disappeared.", "Severity is High because precision rules can silently lose evidence when required fields disappear.", "Protocol mix changes can legitimately reduce coverage for protocol-specific fields.", "Compare parser version and capture-source changes.", "Run regression samples for rules depending on the affected field."));
            return MatchPlatformHealth(context, SeverityLevel.High, "Telemetry field coverage dropped", "TelemetryFieldCoverageDrop", evidence,
                c => { c.AddEvidence(0.32, "platform-health-anchor"); c.AddEvidence(0.28, "coverage-drop-signal"); c.AddEvidence(0.20, "field-or-component-identity"); }, cooldownKey: field);
        }
    }
}
