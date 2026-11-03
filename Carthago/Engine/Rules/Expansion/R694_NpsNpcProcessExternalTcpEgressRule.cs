// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2543.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R694_NpsNpcProcessExternalTcpEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R694", Name: "NPS npc.exe process associated with external TCP egress", Category: "EvasionTunnel",
            Description: "NPS npc.exe process associated with external TCP egress. No NPS command line, vkey/password, server mode, proxy handshake or actual traffic forwarding is observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R694.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R694", Name = "NPS npc.exe process associated with external TCP egress", Category = "EvasionTunnel",
            Description = "Workbook R2543. R263's proxy-process list excludes npc.exe; this candidate is exact-process external TCP evidence for the NPS client binary. No NPS command line, vkey/password, server mode, proxy handshake or actual traffic forwarding is observed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow,RuleTelemetryKind.Process },
            RequiredFields = new[] { "source","destination","process.name","process.id","protocol_or_port" },
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
            FalsePositives = new[] { "No NPS command line, vkey/password, server mode, proxy handshake or actual traffic forwarding is observed. Authorized administration, troubleshooting and security tooling may produce similar traffic." },
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

        public R694_NpsNpcProcessExternalTcpEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research686Evidence.ToolExternalTcp(r, "npc.exe")) return NoMatch();
            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2543", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_tool_network_shape", "rule"),
                new DetectionEvidenceItem("outcome", "named_proxy_tool_tcp_egress_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Named tunneling/proxy-capable process associated with external TCP flow; tunnel unknown", evidence, confidence =>
                {
                    confidence.AddEvidence(0.44, "typed-network-and-process-evidence");
                    confidence.AddEvidence(0.34, "specific-workbook-derived-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
