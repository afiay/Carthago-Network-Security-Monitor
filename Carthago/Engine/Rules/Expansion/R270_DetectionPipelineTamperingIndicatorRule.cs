// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R270_DetectionPipelineTamperingIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R270_DetectionPipelineTamperingIndicatorRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R270",
            Name: "Detection Pipeline Tampering Indicator",
            Category: "EvasionInfra",
            Description: "Detects detection pipeline tampering indicator only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R270.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R270",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(45),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Planned maintenance and controlled test-mode changes must be represented as explicit maintenance context to suppress this rule." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R270 evidence-gated sample", "negative R270 descriptor-only sample", "negative R270 missing telemetry sample" });

        public R270_DetectionPipelineTamperingIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Packet descriptions, process names, HTTP paths and DNS fields cannot
            // attest to changes in the sensor/journal/rule-engine control plane.
            // No trusted typed pipeline-tamper producer is connected to TrafficRecord.
            // Fail closed rather than emit an unsupported Critical tamper finding.
            return NoMatch();
        }
    }
}
