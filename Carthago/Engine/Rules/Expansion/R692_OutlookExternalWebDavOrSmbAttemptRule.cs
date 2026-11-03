// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R3036.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R692_OutlookExternalWebDavOrSmbAttemptRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R692", Name: "Outlook-associated external WebDAV request or SMB SYN attempt", Category: "IdentityAccess",
            Description: "Outlook-associated external WebDAV request or SMB SYN attempt. The original registry-access evidence is unavailable. Network activity does not prove CVE-2023-23397 exploitation, NTLM disclosure, or credential capture.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R692.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R692", Name = "Outlook-associated external WebDAV request or SMB SYN attempt", Category = "IdentityAccess",
            Description = "Workbook R3036. R174 detects inbound WebDAV abuse and R665 Explorer WebDAV→SMB sequence; this requires Outlook process/PID and external resource traffic. The original registry-access evidence is unavailable. Network activity does not prove CVE-2023-23397 exploitation, NTLM disclosure, or credential capture.",
            Severity = SeverityLevel.Medium,
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
            FalsePositives = new[] { "The original registry-access evidence is unavailable. Network activity does not prove CVE-2023-23397 exploitation, NTLM disclosure, or credential capture. Authorized administration, troubleshooting and security tooling may produce similar traffic." },
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

        public R692_OutlookExternalWebDavOrSmbAttemptRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research686Evidence.ExternalSmbSyn(r, "outlook.exe")
            && !Research686Evidence.ExternalWebDav(r, "outlook.exe"))
            return NoMatch();
            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R3036", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_outlook_network_shape", "rule"),
                new DetectionEvidenceItem("outcome", "outlook_external_resource_attempt_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Outlook-associated external WebDAV/SMB attempt observed; exploitation unknown", evidence, confidence =>
                {
                    confidence.AddEvidence(0.44, "typed-network-and-process-evidence");
                    confidence.AddEvidence(0.34, "specific-workbook-derived-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
