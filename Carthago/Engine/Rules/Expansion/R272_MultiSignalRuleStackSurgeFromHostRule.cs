// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R272_MultiSignalRuleStackSurgeFromHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R272_MultiSignalRuleStackSurgeFromHostRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R272",
            Name: "Multi-Signal Rule Stack Surge From Host",
            Category: "EvasionInfra",
            Description: "Detects multi-signal rule stack surge from host only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R272.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R272",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "Requires distinct emitted rule-engine events with rule IDs, family, host, timestamp and provenance.",
                "No trusted per-host detection-event correlation adapter is connected to TrafficRecord.",
                "Fail closed until a trusted rule-event correlation adapter exists."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 82,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Demo mode, replay tests, and synthetic validation runs can intentionally create multi-signal surges." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R272 evidence-gated sample", "negative R272 descriptor-only sample", "negative R272 missing telemetry sample" });

        public R272_MultiSignalRuleStackSurgeFromHostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // A packet record contains no rule-engine alert IDs, family identifiers,
            // correlation provenance or distinct emitted detections. Counting
            // destinations or packet descriptions would fabricate a rule-stack surge.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "TRUSTED_RULE_EVENT_CORRELATION_UNAVAILABLE",
                "R272 requires distinct, authenticated rule-engine detection events; packet traffic is not a substitute.");
        }
    }
}
