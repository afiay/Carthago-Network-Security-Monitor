// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2778.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R875_PublicDnp3SynThenPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R875", Name: "Public DNP3-port TCP SYN followed by application-sized data", Category: "InitialAccess",
            Description: "One public client sends TCP SYN then application-sized TCP data to the same private TCP/20000 host within 40s; no DNP3 decoder, authenticated session or device command is implied.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R875.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R875", Name = "Public DNP3-port TCP SYN followed by application-sized data", Category = "InitialAccess",
            Description = "workbook.R2778: One public client sends TCP SYN then application-sized TCP data to the same private TCP/20000 host within 40s; no DNP3 decoder, authenticated session or device command is implied.", Severity = SeverityLevel.Medium,
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(40), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_dnp3_port_syn_then_same_peer_tcp_payload",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R875_PublicDnp3SynThenPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 20000 || r.HttpMethod != null || r.HttpUri != null
                || r.Sni != null || r.TlsVersion != null || r.DnsQname != null)
                return NoMatch();
            var key = r.Source! + "|" + r.Destination!;
            if (Research676Evidence.Syn(r))
            { _stages.Observe(key, r.Id, context.TimestampUtc, true, 40); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || r.L4Len is < 128 or > 1024
                || !_stages.Observe(key, r.Id, context.TimestampUtc, false, 40))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2778", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_dnp3_port_syn_then_same_peer_tcp_payload", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public DNP3-port TCP SYN followed by application-sized data; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 40);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

