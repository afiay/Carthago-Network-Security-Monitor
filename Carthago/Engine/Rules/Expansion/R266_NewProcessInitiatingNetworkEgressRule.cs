// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R266_NewProcessInitiatingNetworkEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R266_NewProcessInitiatingNetworkEgressRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R266",
            Name: "New Process Initiating Network Egress",
            Category: "EvasionInfra",
            Description: "Detects new process initiating network egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R266.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R266",
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
            minimumConfidence: 75,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Software installs, updates, and newly deployed business applications can naturally create first-seen egress." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R266 evidence-gated sample", "negative R266 descriptor-only sample", "negative R266 missing telemetry sample" });

        public R266_NewProcessInitiatingNetworkEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!(IsOutboundExternal(record) && !string.IsNullOrWhiteSpace(record.ProcessName) && FirstTimeSeen($"process-egress:{record.Source}:{ProcessKey(record)}", context.TimestampUtc)))
                return NoMatch();

            var count = 1;
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "NewProcessEgress,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source/process pair was not previously observed initiating outbound external traffic in the local baseline.",
                "Severity is Low because first-seen process egress is weak alone but valuable for correlation with downloads, interpreters, or suspicious destinations.",
                "Software installs, updates, and newly deployed business applications can naturally create first-seen egress.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.Low,
                "Previously unseen process initiated external network egress",
                "NewProcessEgress",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:NewProcessEgress");
        }
    }
}
