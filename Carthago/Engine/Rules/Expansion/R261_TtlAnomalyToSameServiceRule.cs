// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R261_TtlAnomalyToSameServiceRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R261_TtlAnomalyToSameServiceRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R261",
            Name: "TTL Anomaly To Same Service",
            Category: "EvasionInfra",
            Description: "Detects ttl anomaly to same service only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R261.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R261",
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
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Asymmetric routing, tunnels, load balancers, and path changes can naturally change TTL values." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R261 evidence-gated sample", "negative R261 descriptor-only sample", "negative R261 missing telemetry sample" });

        public R261_TtlAnomalyToSameServiceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!(HasTtlAnomalyContext(record, out var ttlValue)))
                return NoMatch();

            var count = CountWithin($"ttl-anomaly:{record.Source}:{record.Destination}:{record.DestinationPort ?? 0}", context.TimestampUtc, TimeSpan.FromMinutes(15));
            if (!(count >= 3))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "TtlAnomaly,evidence_gated,threshold_met", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            if (!string.IsNullOrWhiteSpace(ttlValue)) evidence.Add(new DetectionEvidenceItem("network.ttl", ttlValue, "network"));
            evidence.AddRange(AnalystContext(
                "Telemetry explicitly reported a TTL or hop-limit mismatch for traffic to the same service.",
                "Severity is Low because TTL anomalies are weak alone, but useful when combined with spoofing, routing, proxy, or scanner evidence.",
                "Asymmetric routing, tunnels, load balancers, and path changes can naturally change TTL values.",
                "Verify the source host role, owner, and recent process/startup changes.",
                "Pivot on destination host, destination port, process name, and adjacent detections in the same time window.",
                "Tune approved business systems explicitly instead of weakening the rule globally."));

            return MatchEvasionInfra(
                context,
                SeverityLevel.Low,
                "TTL/hop-limit anomaly observed toward the same service",
                "TtlAnomaly",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "concrete-evidence");
                    confidence.AddEvidence(0.22, "source-context");
                    confidence.AddEvidence(0.18, "threshold-or-baseline");
                },
                count: count,
                window: Profile.Window,
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.DestinationPort ?? 0}:TtlAnomaly");
        }
    }
}
