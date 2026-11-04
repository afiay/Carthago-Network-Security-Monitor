// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1850.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R754_MacTransferToolPrivatePeerPayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R754",
            Name: "macOS-style transfer tool private-peer payload burst",
            Category: "LateralMovement",
            Description: "scp, sftp, or rsync is associated with four substantial TCP payload observations to one private peer on port 22 or 873 within two minutes. File identity, remote authentication, transfer direction, unique bytes, execution on the destination and lateral compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R754.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R754",
            Name = "macOS-style transfer tool private-peer payload burst",
            Category = "LateralMovement",
            Description = "workbook.R1850: the source analytic correlates macOS transfer utilities with executable movement and follow-on execution. Carthago lacks file creation/execution audit, so this candidate retains exact transfer-tool attribution and a private-peer payload burst only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "process.name", "process.id", "l4.length" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent private-to-private TCP payload observations and exact scp/sftp/rsync attribution.",
                "Require four unique packet IDs and a bounded observed-packet-byte threshold.",
                "Only the private-peer transfer shape is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject public endpoints, wrong ports, missing process attribution, contradictory protocol fields and free-form Info-only assertions.",
                "Reject duplicate IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer file identity, authentication, transfer direction, destination execution or lateral compromise."
            },
            FalsePositives = new[] { "Administration, deployment, backup, cluster synchronization and developer workflows commonly use scp, sftp or rsync between private hosts." },
            MinimumConfidence = 82,
            WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(120),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_source+transfer_process+private_peer+ssh_or_rsync_payload_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive private-peer transfer shape and external-peer near miss",
                "missing and contradictory producer fields",
                "duplicate IDs, reverse time and expiry",
                "cooldown suppression and recovery",
                "evidence privacy, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research666TimedWindow _timed = new();

        public R754_MacTransferToolPrivatePeerPayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research746Evidence.MacLateralPayload(r)
                || !Research746Evidence.MacLateralTransferProcess(r)
                || r.L4Len is null or < 900 or > 8192
                || !_timed.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, r.L4Len.Value, context.TimestampUtc, 4, false, 5000))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1850", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mac_transfer_tool_private_peer_payload_burst", "rule"),
                new DetectionEvidenceItem("outcome", "private_transfer_shape_only_file_and_lateral_outcome_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Transfer-tool private-peer payload burst observed; file identity, authentication, unique bytes, destination execution and lateral compromise are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 4,
                windowSeconds: 120);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
