// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1258.
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R757_LlmnrNbnsConflictThenSmbRelayShapeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R757",
            Name: "LLMNR/NBNS conflicting response followed by SMB connection to responder",
            Category: "LateralMovement",
            Description: "A parser-corroborated unicast conflicting LLMNR/NBNS response from one private host is followed within 60 seconds by a TCP SYN from the same peer to that responder on SMB/445. Credential interception, NTLM relay classification, authentication and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R757.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R757",
            Name = "LLMNR/NBNS conflicting response followed by SMB connection to responder",
            Category = "LateralMovement",
            Description = "workbook.R1258: the source analytic combines LLMNR/NBT-NS poisoning with SMB relay. R083 detects repeated conflicting name-service responses and R082 requires independent relay classification; this candidate correlates a single typed conflict response with a subsequent SMB connection attempt from the same peer.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "conflicting_name_service_response", "private_responder", "private_peer", "smb.syn" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this independent rule-specific predicate.",
                "Process identity, where used, is best-effort local tuple enrichment rather than authenticated endpoint identity.",
                "Stateful rules accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired sequences and cooldown repeats.",
                "Do not infer file access, credentials, command-line arguments, successful authentication, exploit success, C2 control, transfer completion or compromise."
            },
            FalsePositives = new[] { "Legitimate name-resolution conflicts followed by ordinary SMB access can create the same temporal sequence in noisy Windows networks." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_responder+same_name_service_peer+smb445_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped sample and rule-specific benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse-time and expiry where stateful",
                "cooldown suppression and recovery",
                "privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research756PeerSequenceWindow _sequence = new();

        public R757_LlmnrNbnsConflictThenSmbRelayShapeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research756Evidence.LlmnrNbnsConflict(context, out var responder, out var peer))
                {
                    _sequence.Observe(responder, peer, r.Id, context.TimestampUtc, true, 60);
                    return NoMatch();
                }
            
                if (!Research756Evidence.SmbSynToResponder(r)
                    || !_sequence.Observe(r.Destination!, r.Source!, r.Id, context.TimestampUtc, false, 60))
                    return NoMatch();

            var cool = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (cool == WebSignatureObservation.None) return NoMatch();
            if (cool == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1258", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "llmnr_nbns_conflict_then_same_peer_smb_syn", "rule"),
                new DetectionEvidenceItem("outcome", "name_service_conflict_and_smb_sequence_only_relay_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Conflicting LLMNR/NBNS response followed by same-peer SMB connection attempt observed; poisoning ownership, NTLM relay, authentication and compromise are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 60);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
