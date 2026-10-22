// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R269_SecurityToolUpdateBlockIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R269_SecurityToolUpdateBlockIndicatorRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R269",
            Name: "Security Tool Update Block Indicator",
            Category: "EvasionInfra",
            Description: "Detects security tool update block indicator only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R269.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R269",
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
            threshold: 3,
            window: TimeSpan.FromMinutes(30),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Outages, maintenance windows, captive portals, and proxy misconfiguration can produce legitimate failures." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R269 evidence-gated sample", "negative R269 descriptor-only sample", "negative R269 missing telemetry sample" });

        public R269_SecurityToolUpdateBlockIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!(HasSecurityToolUpdateBlockContext(record)))
                return NoMatch();

            var count = CountWithin($"security-update-block:{record.Source}:{BestHost(record)}", context.TimestampUtc, TimeSpan.FromMinutes(30));
            if (!(count >= 3))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "SecurityUpdateBlock,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext(
                "Telemetry combines security-update/threat-feed context with DNS, connection, HTTP, or reset failure evidence.",
                "Severity is Medium because blocked security updates can indicate tampering, sinkholing, proxy issues, or defensive blind spots.",
                "Outages, maintenance windows, captive portals, and proxy misconfiguration can produce legitimate failures.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.Medium,
                "Security tool update or threat-feed retrieval appears blocked or failing",
                "SecurityUpdateBlock",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:SecurityUpdateBlock");
        }
    }
}
