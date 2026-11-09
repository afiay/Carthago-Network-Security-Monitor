// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R1700.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R811_ExpiredCertificateUnusualTlsPortRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R811",
            Name: "Repeated expired remote TLS certificates on service port 9443",
            Category: "ProtocolIntelligence",
            Description: "Repeated expired remote TLS certificates on service port 9443. Observable packet/process shape only; no authorization, causality, success or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R811.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R811",
            Name = "Repeated expired remote TLS certificates on service port 9443",
            Category = "ProtocolIntelligence",
            Description = "workbook.R1700: This requires captured certificate validity and two client ports but does not inspect RSA, certificate chains, or key-exchange validity.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "packet.id", "cert.issuer", "cert.subject", "cert.valid.to", "source.port" },
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
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R811_expired_cert_server9443_multiple_client_ports",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();

        public R811_ExpiredCertificateUnusualTlsPortRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.SourcePort != 9443 || string.IsNullOrWhiteSpace(r.CertIssuer)
                || string.IsNullOrWhiteSpace(r.CertSubject)
                || r.CertIssuer.Length > 256 || r.CertSubject.Length > 256
                || string.Equals(r.CertIssuer, r.CertSubject, StringComparison.Ordinal)
                || !r.CertValidTo.HasValue || r.CertValidTo.Value >= context.TimestampUtc.AddDays(-30)
                || r.HttpMethod != null || r.DnsQname != null
                || !_distinct.Observe(r.Source! + "|" + r.CertIssuer,
                    r.DestinationPort!.Value.ToString(), r.Id, context.TimestampUtc, 2, 90))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1700", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r811_expired_cert_server9443_multiple_client_ports", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Repeated expired remote TLS certificates on service port 9443 observed; asset role, causal context and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_local_process_evidence");
                    confidence.AddEvidence(0.33, "independent_workbook_sourced_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_packet_correlation");
                },
                count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
