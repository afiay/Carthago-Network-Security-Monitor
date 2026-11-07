// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R1917.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R774_MacScreensharingdPublicVncSynAckRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R774",
            Name: "macOS screensharingd public VNC SYN-ACK",
            Category: "RemoteAccess",
            Description: "screensharingd is associated with a private-host TCP/5900 SYN-ACK to a public client. Unified-log login evidence, authentication, remote-control session establishment, user interaction and authorization are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R774.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R774",
            Name = "macOS screensharingd public VNC SYN-ACK",
            Category = "RemoteAccess",
            Description = "workbook.R1917: the macOS VNC analytic combines screensharingd activity with remote login/user interaction. Carthago keeps the macOS-specific process attribution plus public-client VNC handshake response only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "tcp.flags", "source.port", "process.name", "process.id" },
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
            FalsePositives = new[] { "Authorized Apple Screen Sharing, remote support, lab access and administrator maintenance can legitimately expose VNC." },
            MinimumConfidence = 84,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_screensharingd+public_client+vnc_synack",
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

        public R774_MacScreensharingdPublicVncSynAckRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.MacScreensharingPublicSynAck(r))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1917", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "screensharingd_public_vnc_synack", "rule"),
                new DetectionEvidenceItem("outcome", "vnc_handshake_response_only_authentication_and_session_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "macOS screensharingd public VNC SYN-ACK observed; authentication, session establishment, user interaction and authorization are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
