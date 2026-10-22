// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R262_SuspiciousPacketFragmentationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R262_SuspiciousPacketFragmentationRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R262",
            Name: "Suspicious Packet Fragmentation",
            Category: "EvasionInfra",
            Description: "Detects suspicious packet fragmentation only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R262.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R262",
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
            minimumConfidence: 82,
            threshold: 2,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Path MTU issues, tunnels, and legacy devices can fragment traffic; tune known tunnel endpoints." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R262 evidence-gated sample", "negative R262 descriptor-only sample", "negative R262 missing telemetry sample" });

        public R262_SuspiciousPacketFragmentationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!(HasSuspiciousFragmentationContext(record)))
                return NoMatch();

            var count = CountWithin($"fragment:{record.Source}:{record.Destination}:{record.DestinationPort ?? 0}", context.TimestampUtc, TimeSpan.FromMinutes(10));
            if (!(count >= 2))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "Fragmentation,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext(
                "Fragmentation telemetry indicates overlap, tiny fragments, offset abuse, or explicit evasion-like fragmentation.",
                "Severity is High because overlapping or tiny fragments are common evasive delivery patterns against inspection and reassembly logic.",
                "Path MTU issues, tunnels, and legacy devices can fragment traffic; tune known tunnel endpoints.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.High,
                "Suspicious packet fragmentation pattern observed",
                "Fragmentation",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:Fragmentation");
        }
    }
}
