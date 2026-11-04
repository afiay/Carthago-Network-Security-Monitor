// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2415.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R700_Rundll32ExternalWebDavRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R700", Name: "Rundll32-associated external WebDAV request", Category: "EvasionInfra",
            Description: "Rundll32-associated external WebDAV request. DavSetCookie command line, parent process, code launch and CVE exploitation are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R700.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R700", Name = "Rundll32-associated external WebDAV request", Category = "EvasionInfra",
            Description = "Workbook R2415: R174 is inbound WebDAV abuse and R692 is Outlook-specific; this requires private-to-public WebDAV plus Rundll32 PID/name. DavSetCookie command line, parent process, code launch and CVE exploitation are not observed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source","destination_or_host","process.name","process.id","http.method","http.uri" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require typed packet/process fields and this rule's exact independent predicate.",
                "Where process identity is required it is best-effort local tuple enrichment, not an authenticated endpoint event.",
                "Where a sequence is required, only bounded unique packet IDs from one relay/peer context can satisfy it."
            },
            NegativeConditions = new[]
            {
                "Reject missing producer fields, wrong method/transport/direction and free-form Info-only indicators.",
                "Reject duplicates, out-of-order timestamps, expired sequences and cooldown repeats.",
                "Do not infer transfer completion, credentials, C2, proxy forwarding, CVE exploitation or device compromise."
            },
            FalsePositives = new[] { "DavSetCookie command line, parent process, code launch and CVE exploitation are not observed. Authorized software distribution, administration and security testing may resemble this signal." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "independent_rule_specific_process_peer_or_sequence",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "exact positive and benign near miss", "wrong process/method/protocol or network direction",
                "missing process attribution or explicit no-process gate where required",
                "duplicate/out-of-order/expiry and cooldown", "Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        

        public R700_Rundll32ExternalWebDavRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research686Evidence.ExternalWebDav(r, "rundll32.exe")) return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2415", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_webdav_shape", "rule"),
                new DetectionEvidenceItem("outcome", "external_webdav_request_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Rundll32-associated external WebDAV request observed; DavSetCookie command line, parent process, code launch and CVE exploitation are not observed.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "coherent-source-destination-or-sequence");
                }, count: 1, windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
