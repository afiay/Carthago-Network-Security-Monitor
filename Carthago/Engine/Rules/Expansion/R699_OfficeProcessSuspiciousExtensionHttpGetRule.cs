// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2315.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R699_OfficeProcessSuspiciousExtensionHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R699", Name: "Office process cleartext HTTP GET for executable or script-like path", Category: "HttpApi",
            Description: "Office process cleartext HTTP GET for executable or script-like path. Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R699.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R699", Name = "Office process cleartext HTTP GET for executable or script-like path", Category = "HttpApi",
            Description = "Workbook R2315: R690 is Curl-specific; this requires an Office process/PID and a suspicious extension on a public HTTP GET. Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download.",
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
            FalsePositives = new[] { "Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download. Authorized software distribution, administration and security testing may resemble this signal." },
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
        

        public R699_OfficeProcessSuspiciousExtensionHttpGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research696Evidence.OfficeSuspiciousGet(r)) return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2315", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "independent_office_shape", "rule"),
                new DetectionEvidenceItem("outcome", "office_http_get_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Office process cleartext HTTP GET for executable or script-like path observed; Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download.",
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
