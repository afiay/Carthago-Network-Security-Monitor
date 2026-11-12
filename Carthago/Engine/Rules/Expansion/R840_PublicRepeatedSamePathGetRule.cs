// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1339.
using System;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R840_PublicRepeatedSamePathGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R840", Name: "Same public client repeated HTTP GET to private service path", Category: "Impact",
            Description: "Eight coherent same-path public-to-private cleartext HTTP/80 GET packets over twenty seconds; no network-layer denial-of-service impact or resource depletion inferred.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R840.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R840", Name = "Same public client repeated HTTP GET to private service path", Category = "Impact",
            Description = "workbook.R1339: Eight coherent same-path public-to-private cleartext HTTP/80 GET packets over twenty seconds; no network-layer denial-of-service impact or resource depletion inferred.",
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
            MinimumConfidence = 80, WindowThreshold = 8,
            Window = TimeSpan.FromSeconds(20), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_repeated_same_path_get",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "specific positive/benign case", "missing/contradictory evidence",
                "duplicate and expired observation", "cooldown recovery", "raw Info excluded",
                "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _burst = new();
        public R840_PublicRepeatedSamePathGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 80 || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || r.L4Len is not int payloadLength || payloadLength is < 200 or > 2048) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + uri;
            if (!_burst.Observe(key, r.Id, payloadLength, context.TimestampUtc, 8, 20, 3200)) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1339", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_repeated_same_path_get", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Same public client repeated HTTP GET to private service path observed; provenance, authorization and outcome unverified.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_independent_observable_predicate");
                    confidence.AddCorrelation(0.12, "bounded_utc_correlation");
                }, count: 8, windowSeconds: 20);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

