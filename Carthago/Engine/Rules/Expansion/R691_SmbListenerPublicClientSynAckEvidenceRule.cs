// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2300.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R691_SmbListenerPublicClientSynAckEvidenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R691", Name: "Private SMB listener SYN-ACK response to a public client", Category: "IdentityAccess",
            Description: "Private SMB listener SYN-ACK response to a public client. The original Event 4624 successful logon is not available. SYN-ACK proves only a TCP listener response, not SMB authentication or successful login.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R691.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R691", Name = "Private SMB listener SYN-ACK response to a public client", Category = "IdentityAccess",
            Description = "Workbook R2300. R351 requires parser-attributed NTLM and R026 observes SMB/RPC internet traffic; this specifically requires server-to-public-client TCP SYN-ACK from source port 445. The original Event 4624 successful logon is not available. SYN-ACK proves only a TCP listener response, not SMB authentication or successful login.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source","destination","tcp.flags","source.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent packet fields plus the exact process/service predicate for this rule.",
                "Process/PID association is best-effort local tuple enrichment and is not authenticated endpoint telemetry.",
                "Only request, SYN, SYN-ACK, host contact, or external TCP evidence is established."
            },
            NegativeConditions = new[]
            {
                "Reject missing process identity when required, wrong network boundary, wrong method/service, and Info-only hints.",
                "Reject packet duplicates, out-of-order timestamps and repeated observations during cooldown.",
                "Never claim file download, credential capture, successful logon, CVE exploitation or established tunnel."
            },
            FalsePositives = new[] { "The original Event 4624 successful logon is not available. SYN-ACK proves only a TCP listener response, not SMB authentication or successful login. Authorized administration, troubleshooting and security tooling may produce similar traffic." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "exact_rule_process_and_peer_or_service_shape",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive and benign near miss", "missing PID/process and wrong network boundary",
                "wrong method, host, service or transport", "duplicate ID, stale time and cooldown",
                "fixed evidence and Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R691_SmbListenerPublicClientSynAckEvidenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.SynAck(r)
            || !Research646Evidence.Pair(r, false, out _, out _)
            || r.SourcePort != 445 || r.DestinationPort is null or <= 0 or > 65535)
            return NoMatch();
            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2300", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_smbsynack_network_shape", "rule"),
                new DetectionEvidenceItem("outcome", "smb_tcp_syn_ack_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "SMB listener TCP SYN-ACK to public client observed; authentication unknown", evidence, confidence =>
                {
                    confidence.AddEvidence(0.44, "typed-network-and-process-evidence");
                    confidence.AddEvidence(0.34, "specific-workbook-derived-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
