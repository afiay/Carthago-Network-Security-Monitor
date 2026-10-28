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

        private readonly NetworkBatch261265Evidence.TtlWindow _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch261265Evidence.ValidFlow(r) || !NetworkBatch261265Evidence.Ttl(r, out var ttl)) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + (r.DestinationPort ?? 0);
            var count = _observations.Observe(r, context.TimestampUtc, key, ttl);
            if (count < 3) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "wire_ttl,instance_scoped_change,distinct_packet_ids", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("network.ttl", ttl.ToString(System.Globalization.CultureInfo.InvariantCulture), "network")
            };
            evidence.AddRange(AnalystContext("Three distinct packets to the same service show a TTL spread of at least 16 within 15 minutes.",
                "TTL spread is a path-change indicator, not evidence of spoofing or a malicious actor.",
                "Routing asymmetry, NAT, VPNs and load balancing can change observed TTL.",
                "Compare route changes with approved network maintenance."));
            return MatchEvasionInfra(context, SeverityLevel.Low, "Observed TTL spread toward same service (path anomaly only)",
                "TtlAnomaly", evidence, c => { c.AddEvidence(0.34, "wire-ttl"); c.AddEvidence(0.22, "same-service"); c.AddEvidence(0.18, "distinct-packets"); },
                count: count, window: Profile.Window, cooldownKey: key + ":ttl-spread");
        }
    }
}
