// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2846.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R844_LowTtlDnsAnswerChurnRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R844", Name: "Three low-TTL single-IP DNS A answers changing over time", Category: "CommandControl",
            Description: "Same public DNS resolver sends three distinct single-public-IPv4 A answers with TTL 1-30s to one private client for one qname within 45s; not a fast-flux or C2 verdict.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R844.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R844", Name = "Three low-TTL single-IP DNS A answers changing over time", Category = "CommandControl",
            Description = "workbook.R2846: Same public DNS resolver sends three distinct single-public-IPv4 A answers with TTL 1-30s to one private client for one qname within 45s; not a fast-flux or C2 verdict.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(45), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "low_ttl_single_answer_temporal_dns_churn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _answers = new();
        public R844_LowTtlDnsAnswerChurnRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.SourcePort != 53 || !r.DnsIsResponse || !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname.Length > 253
                || r.DnsTtl is < 1 or > 30 || r.HttpMethod != null || r.HttpUri != null
                || r.TlsVersion != null || r.Sni != null
                || !IPAddress.TryParse(r.DnsAnswers, out var answer) || !Research646Evidence.Public(answer)) return NoMatch();
            var key = r.Destination! + "|" + r.Source! + "|" + r.DnsQname.ToLowerInvariant();
            if (!_answers.Observe(key, answer.ToString(), r.Id, context.TimestampUtc, 3, 45)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R2846", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "low_ttl_single_answer_temporal_dns_churn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Three low-TTL single-IP DNS A answers changing over time observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 3, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

