// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R1391.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R807_PublicSshServiceThenEastWestSshRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R807",
            Name: "Public SSH service reply followed by local east-west SSH SYN",
            Category: "LateralMovement",
            Description: "Public SSH service reply followed by local east-west SSH SYN. Observable packet/process shape only; no authorization, causality, success or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R807.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R807",
            Name = "Public SSH service reply followed by local east-west SSH SYN",
            Category = "LateralMovement",
            Description = "workbook.R1391: No SSH authentication, delegated trust or sudo event is observed; only successive SSH-related TCP SYN-ACK and SYN legs.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "tcp.flags", "process.id", "source.port", "destination.port" },
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
            DistinctBy = "R807_public_ssh_reply_then_internal_ssh_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R807_PublicSshServiceThenEastWestSshRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (Research786NetworkEvidence.PrivatePublic(r)
                && Research676Evidence.SynAck(r) && r.SourcePort == 22
                && Research676Evidence.Process(r, "sshd", "sshd.exe"))
            {
                _sequence.Observe(r.Source!, r.Id, context.TimestampUtc, true, 90);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.Internal(r) || !Research676Evidence.Syn(r)
                || r.DestinationPort != 22 || !Research676Evidence.Process(r, "ssh", "ssh.exe")
                || !_sequence.Observe(r.Source!, r.Id, context.TimestampUtc, false, 90))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1391", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r807_public_ssh_reply_then_internal_ssh_syn", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public SSH service reply followed by local east-west SSH SYN observed; asset role, causal context and outcome unknown.",
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
