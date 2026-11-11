// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R1743.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R891_PublicVncSynThenPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R891", Name: "Public VNC SYN followed by same-flow client data", Category: "InitialAccess",
            Description: "Public SYN/5900 to private host followed by client application-sized data on the same source port within 40s; VNC authentication, session takeover, GUI action and file transfer are not observed.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R891.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R891", Name = "Public VNC SYN followed by same-flow client data", Category = "InitialAccess",
            Description = "workbook.R1743: Public SYN/5900 to private host followed by client application-sized data on the same source port within 40s; VNC authentication, session takeover, GUI action and file transfer are not observed.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "source.port", "tcp.flags", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(40), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_vnc5900_syn_then_same_flow_client_data",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R891_PublicVncSynThenPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 5900 || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.TlsVersion != null || r.Sni != null) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.SourcePort;
            if (Research676Evidence.Syn(r))
            { _stages.Observe(key, r.Id, context.TimestampUtc, true, 40); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || r.L4Len is < 250 or > 1600
                || !_stages.Observe(key, r.Id, context.TimestampUtc, false, 40)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1743", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_vnc5900_syn_then_same_flow_client_data", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public VNC SYN followed by same-flow client data; authentication, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_evidence");
                    confidence.AddEvidence(0.33, "owner_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_correlation");
                }, count: 2, windowSeconds: 40);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
