// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R1599.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R810_FrpcQuicPublicPeerFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R810",
            Name: "frpc-attributed versioned QUIC fanout to three public peers",
            Category: "EvasionTunnel",
            Description: "frpc-attributed versioned QUIC fanout to three public peers. Observable packet/process shape only; no authorization, causality, success or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R810.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R810",
            Name = "frpc-attributed versioned QUIC fanout to three public peers",
            Category = "EvasionTunnel",
            Description = "workbook.R1599: QUIC fanout does not establish multi-hop proxying, ESXi execution, or relay ownership; no connection ID hash is assumed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "quic.version", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Typed and mutually coherent transport/direction fields plus the narrow independent predicate.",
                "Bounded instance-owned monotonic UTC state and distinct packet provenance; not live validation."
            },
            NegativeConditions = new[]
            {
                "Incomplete/contradictory process, protocol, port, peer or context, duplicate IDs and stale time fail closed.",
                "No free-form Info assertion, secret, raw payload, endpoint audit, authorization or success claim."
            },
            FalsePositives = new[]
            {
                "Approved operations, maintenance, diagnostics and scripted administration can produce similar traffic."
            },
            MinimumConfidence = 80,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R810_frpc_quic_three_public_peers",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();

        public R810_FrpcQuicPublicPeerFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || !r.IsUdp || r.IsTcp || !r.IsQuic
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.TcpFlags != null || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort != 443 || r.L4Len is null or < 64 or > 1400
                || r.Length < r.L4Len.Value + 28
                || string.IsNullOrWhiteSpace(r.QuicVersion) || r.QuicVersion.Length > 64
                || r.HttpMethod != null || r.DnsQname != null || r.TlsVersion != null
                || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "frpc", "frpc.exe")
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId,
                    r.Destination!, r.Id, context.TimestampUtc, 3, 60))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1599", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r810_frpc_quic_three_public_peers", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "frpc-attributed versioned QUIC fanout to three public peers observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_local_process_evidence");
                    confidence.AddEvidence(0.33, "independent_workbook_sourced_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_packet_correlation");
                },
                count: 3, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
