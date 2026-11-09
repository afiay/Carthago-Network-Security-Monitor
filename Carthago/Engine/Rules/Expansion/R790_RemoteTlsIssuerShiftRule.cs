// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; source-only xUnit, 0 tests executed. workbook.R1020.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R790_RemoteTlsIssuerShiftRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R790",
            Name: "Public server certificate issuer changes across captured handshakes",
            Category: "EvasionTunnel",
            Description: "Public server certificate issuer changes across captured handshakes. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R790.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R790",
            Name = "Public server certificate issuer changes across captured handshakes",
            Category = "EvasionTunnel",
            Description = "workbook.R1020: narrowed to actually modeled packet, DNS, HTTP, TLS, and optional local-process telemetry; original audit/outcome evidence is unavailable.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "packet.id", "cert.issuer", "cert.subject", "source.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Only coherent typed fields and this rule's distinct temporal/network predicate qualify.", "Each instance has independent, bounded, monotonic UTC packet-ID correlation state." },
            NegativeConditions = new[] { "Reject duplicate packet ID, reversed time, wrong direction, expired observations, missing or contradictory telemetry.", "Never infer authenticated user, endpoint configuration change, successful file transfer, C2, causal compromise or impact." },
            FalsePositives = new[] { "Authorized administration, failover, service deployment and maintenance may produce matching network sequences." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(180),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R790_independent_issuer_network_predicate",
            TuningKnobs = new[] { "Mode", "ApprovedAssets", "ApprovedProcesses", "ApprovedPeers", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign near miss", "missing/contradictory fields", "replay/reverse-time/expiry", "cooldown recovery", "privacy", "Candidate/Shadow", "non-convergence and unique registry" }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786IssuerShiftWindow _issuer = new();

        public R790_RemoteTlsIssuerShiftRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.SourcePort != 443 || r.DestinationPort is < 1024
                || string.IsNullOrWhiteSpace(r.CertIssuer)
                || string.IsNullOrWhiteSpace(r.CertSubject)
                || r.HttpUri != null || r.DnsQname != null) return NoMatch();
            var key = r.Destination + "|" + r.Source + "|" + r.CertSubject;
            if (!_issuer.Observe(key, r.Id, r.CertIssuer!, context.TimestampUtc)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1020", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r790_issuer_typed_network_observation", "rule"),
                new DetectionEvidenceItem("outcome", "packet_sequence_only_endpoint_intent_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public server certificate issuer changes across captured handshakes observed; causal context, endpoint state and outcomes unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed-observable-network-fields");
                    confidence.AddEvidence(0.33, "workbook-derived-independent-predicate");
                    confidence.AddCorrelation(0.12, "bounded-ordered-evidence");
                },
                count: 2, windowSeconds: 180);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
