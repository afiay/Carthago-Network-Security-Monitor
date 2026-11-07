// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2039.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R775_MacSshdPublicSynAckThenUserToolEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R775",
            Name: "macOS SSH listener response followed by user-tool egress",
            Category: "LateralMovement",
            Description: "An sshd-attributed private-host TCP/22 SYN-ACK to a public client is followed within ninety seconds by outbound public traffic from the same host attributed to zsh, osascript, curl, or python3. Login success, user identity, process parentage, interactive shell state, causality and compromise are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R775.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R775",
            Name = "macOS SSH listener response followed by user-tool egress",
            Category = "LateralMovement",
            Description = "workbook.R2039: the macOS SSH analytic requires login evidence followed by unusual execution. Carthago replaces unavailable login/process-lineage telemetry with a bounded sshd listener-response then user-tool egress sequence.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "private_host", "public_client", "tcp.flags", "source.port", "sshd_process", "follow_on_process" },
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
            FalsePositives = new[] { "Authorized remote administration can legitimately produce an SSH listener response followed by user commands or automation that creates outbound traffic." },
            MinimumConfidence = 82,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_mac_host+sshd_public_synack+user_tool_egress",
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
        private readonly Research756HostSequenceWindow _sequence = new();

        public R775_MacSshdPublicSynAckThenUserToolEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research766Evidence.MacSshdPublicSynAck(r))
                {
                    _sequence.Observe(r.Source!, r.Id, context.TimestampUtc, true, 90);
                    return NoMatch();
                }
            
                if (!Research766Evidence.MacPostSshToolEgress(r)
                    || !_sequence.Observe(r.Source!, r.Id, context.TimestampUtc, false, 90))
                    return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2039", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mac_sshd_public_synack_then_user_tool_egress", "rule"),
                new DetectionEvidenceItem("outcome", "temporal_network_sequence_only_login_and_causality_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "macOS SSH listener response followed by user-tool egress observed; login success, process lineage, causality and compromise are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
