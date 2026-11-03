// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2284.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R689_CurlFileSharingServiceHostEgressRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R689", Name: "Curl-associated contact to selected file-sharing service host", Category: "HttpApi",
            Description: "Curl-associated contact to selected file-sharing service host. The source rule requires command-line download/output flags and suspicious extension; SNI/HTTP host contact alone does not prove a file download.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R689.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R689", Name = "Curl-associated contact to selected file-sharing service host", Category = "HttpApi",
            Description = "Workbook R2284. R111 requires posting/upload context and R657 requires Pastebin API POST; this is a curl-specific GET/TLS contact signal, with no upload predicate. The source rule requires command-line download/output flags and suspicious extension; SNI/HTTP host contact alone does not prove a file download.",
            Severity = SeverityLevel.Low,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow,RuleTelemetryKind.Http,RuleTelemetryKind.Process },
            RequiredFields = new[] { "source","destination","process.name","process.id","http_or_tcp_context" },
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
            FalsePositives = new[] { "The source rule requires command-line download/output flags and suspicious extension; SNI/HTTP host contact alone does not prove a file download. Authorized administration, troubleshooting and security tooling may produce similar traffic." },
            MinimumConfidence = 80,
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

        public R689_CurlFileSharingServiceHostEgressRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research686Evidence.ProcessFileSharingContact(r, "curl.exe", "curl")) return NoMatch();
            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2284", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_fileshare_network_shape", "rule"),
                new DetectionEvidenceItem("outcome", "file_sharing_host_contact_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Low,
                "File-sharing service contact associated with curl process; download outcome unknown", evidence, confidence =>
                {
                    confidence.AddEvidence(0.44, "typed-network-and-process-evidence");
                    confidence.AddEvidence(0.34, "specific-workbook-derived-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
