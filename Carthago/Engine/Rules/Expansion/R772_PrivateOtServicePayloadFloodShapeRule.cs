// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2699.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R772_PrivateOtServicePayloadFloodShapeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R772",
            Name: "High-rate payload traffic to private OT service",
            Category: "IotOtAdvanced",
            Description: "Twenty payload-bearing TCP/UDP observations target one private OT-associated service port within ten seconds. Malformed PDU semantics, approved-controller identity, poll failure, device resource exhaustion, service degradation and denial-of-service impact are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R772.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R772",
            Name = "High-rate payload traffic to private OT service",
            Category = "IotOtAdvanced",
            Description = "workbook.R2699: the embedded DoS analytic requires both high-rate/malformed ICS traffic and device degradation evidence. Carthago retains only the bounded high-rate payload shape on specific OT service ports.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "protocol", "destination.port", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and this rule's exact independent predicate.",
                "Process attribution is best-effort local tuple enrichment, not authenticated endpoint process identity.",
                "Stateful candidates accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command lines, approved asset role, credentials, authentication success, C2 control, transfer completion, DoS impact or compromise."
            },
            FalsePositives = new[] { "Commissioning, stress tests, firmware operations, historian backfill, redundancy convergence and legitimate high-frequency polling may create short OT traffic bursts." },
            MinimumConfidence = 78,
            WindowThreshold = 20,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+private_ot_target+service_port+payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped case and benign near miss",
                "missing/contradictory telemetry",
                "duplicate ID, reverse-time and expiry for stateful candidates",
                "cooldown suppression and recovery",
                "privacy/redaction, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R772_PrivateOtServicePayloadFloodShapeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.OtPayloadPacketToPrivate(r)
                || !_window.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.Protocol,
                    r.Id, r.L4Len!.Value, context.TimestampUtc, 20, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2699", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "private_ot_service_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "ot_packet_rate_only_malformed_pdu_and_dos_impact_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "High-rate payload traffic to a private OT service observed; malformed PDU status, device degradation and denial-of-service outcome are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 20,
                windowSeconds: 10);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
