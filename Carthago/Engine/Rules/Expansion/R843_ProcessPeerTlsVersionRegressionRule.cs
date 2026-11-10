// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2059.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R843_ProcessPeerTlsVersionRegressionRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R843", Name: "Same process and peer TLS 1.3 then TLS 1.0 or 1.1", Category: "DefenseEvasion",
            Description: "Same local curl/python2 process and public peer observed with TLS 1.3 then older TLS 1.0/1.1 within 90 seconds; no negotiated downgrade or exploit confirmed.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R843.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R843", Name = "Same process and peer TLS 1.3 then TLS 1.0 or 1.1", Category = "DefenseEvasion",
            Description = "workbook.R2059: Same local curl/python2 process and public peer observed with TLS 1.3 then older TLS 1.0/1.1 within 90 seconds; no negotiated downgrade or exploit confirmed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Typed IPv4 packet predicate and independent UTC-bounded observation match.",
                "No unobserved endpoint execution, authentication or causality asserted."
            },
            NegativeConditions = new[] {
                "Missing or contradictory typed fields, repeated IDs, reverse UTC order and stale state fail closed.",
                "No encrypted contents interpreted; no benign authorization inferred."
            },
            FalsePositives = new[] {
                "Authorized automation, infrastructure updates, diagnostics and red-team traffic can share the observable shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "process_peer_tls_version_regression",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R843_ProcessPeerTlsVersionRegressionRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord record) =>
            Research786NetworkEvidence.TcpData(record)
            && !string.IsNullOrWhiteSpace(record.TlsVersion) && !string.IsNullOrWhiteSpace(record.Sni)
            && record.HttpMethod == null && record.HttpUri == null && record.DnsQname == null
            && !record.DnsIsResponse
            && !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!ValidTls(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 443 || !Research676Evidence.Process(r, "curl", "curl.exe", "python2", "python2.7")) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (string.Equals(r.TlsVersion, "TLS1.3", StringComparison.OrdinalIgnoreCase))
            {
                _stages.Observe(key, r.Id, context.TimestampUtc, true, 90);
                return NoMatch();
            }
            if (!(string.Equals(r.TlsVersion, "TLS1.0", StringComparison.OrdinalIgnoreCase)
                || string.Equals(r.TlsVersion, "TLS1.1", StringComparison.OrdinalIgnoreCase))
                || !_stages.Observe(key, r.Id, context.TimestampUtc, false, 90)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R2059", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "process_peer_tls_version_regression", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Same process and peer TLS 1.3 then TLS 1.0 or 1.1 observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

