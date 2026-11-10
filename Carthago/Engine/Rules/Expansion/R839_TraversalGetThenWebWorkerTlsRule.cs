// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1230.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R839_TraversalGetThenWebWorkerTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R839", Name: "Public encoded traversal GET then web-worker public TLS", Category: "InitialAccess",
            Description: "Inbound cleartext encoded traversal GET on HTTP/80 followed by w3wp process attributed outbound TLS/8443 from the private web host; exploit success and worker causality unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R839.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R839", Name = "Public encoded traversal GET then web-worker public TLS", Category = "InitialAccess",
            Description = "workbook.R1230: Inbound cleartext encoded traversal GET on HTTP/80 followed by w3wp process attributed outbound TLS/8443 from the private web host; exploit success and worker causality unknown.",
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
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "encoded_traversal_get_then_web_worker_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R839_TraversalGetThenWebWorkerTlsRule() : base(Rule, Profile) { }

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
            if (Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.DestinationPort == 80 && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "GET" && uri.IndexOf("%2e%2e", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                _stages.Observe(r.Destination!, r.Id, context.TimestampUtc, true, 60);
                return NoMatch();
            }
            if (!ValidTls(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 8443 || !Research676Evidence.Process(r, "w3wp.exe", "w3wp")
                || !_stages.Observe(r.Source!, r.Id, context.TimestampUtc, false, 60)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1230", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "encoded_traversal_get_then_web_worker_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public encoded traversal GET then web-worker public TLS observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

