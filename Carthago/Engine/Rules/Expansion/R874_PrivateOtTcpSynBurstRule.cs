// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2705.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R874_PrivateOtTcpSynBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R874", Name: "Private OT TCP/502 SYN burst with unique packets", Category: "Availability",
            Description: "Eight distinct private-to-private TCP/502 SYN packets to the same peer within 30s; this is only a packet-rate shape, not device counter evidence, dropped traffic or proven denial of service.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R874.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R874", Name = "Private OT TCP/502 SYN burst with unique packets", Category = "Availability",
            Description = "workbook.R2705: Eight distinct private-to-private TCP/502 SYN packets to the same peer within 30s; this is only a packet-rate shape, not device counter evidence, dropped traffic or proven denial of service.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent packet-observable predicate.",
                "Per-rule bounded monotonic UTC correlation; no missing producer claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reversed time and expired windows fail closed.",
                "No trusted identity, host audit, changed configuration, authenticated action, exploit, C2 or impact inferred."
            },
            FalsePositives = new[]
            {
                "Authorized network administration, service discovery, maintenance and diagnostics may generate this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 8,
            Window = TimeSpan.FromSeconds(30), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "same_private_pair_eight_tcp502_syn_within_30s",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _burst = new();
        public R874_PrivateOtTcpSynBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r)
                || !Research786NetworkEvidence.Internal(r) || r.DestinationPort != 502
                || r.Sni != null || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null)
                return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|502";
            if (!_burst.Observe(key, r.Id, r.Length, context.TimestampUtc, 8, 30, 320)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2705", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "same_private_pair_eight_tcp502_syn_within_30s", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private OT TCP/502 SYN burst with unique packets; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 8, windowSeconds: 30);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

