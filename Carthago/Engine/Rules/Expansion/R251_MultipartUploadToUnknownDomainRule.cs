// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R251_MultipartUploadToUnknownDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R251_MultipartUploadToUnknownDomainRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R251", "Multipart Upload To Unknown Domain", "ExfiltrationAdvanced", "Detects multipart/form-data uploads to first-seen external domains outside known sanctioned cloud roots.", SeverityLevel.High, "Rules.R251.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R251", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline }, new[] { "source", "external_domain", "multipart_upload", "first_seen_domain" }, new[] { "http.path", "http.method", "matched_conditions" }, new[] { "Upload must use multipart/form-data or filename metadata.", "Destination root domain must be first-seen/recently unknown.", "Known cloud collaboration roots are suppressed." }, new[] { "Do not alert on approved SaaS uploads.", "Do not alert on simple form posts without file-upload metadata." }, 84, 1, TimeSpan.FromHours(24), TimeSpan.FromMinutes(30), "source+root_domain+multipart", new[] { "New business SaaS adoption and vendor portals may match initially." }, new[] { "Mode", "FirstSeenWindow", "ApprovedDomainRoots", "CooldownSeconds" }, new[] { "positive multipart to new domain sample", "negative upload to approved SaaS sample" });
        public R251_MultipartUploadToUnknownDomainRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        private readonly NetworkBatch226230Evidence.Window _firstSeen = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch251255Evidence.Multipart(record)
                || IsLikelyApprovedSyncOrBackup(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var seen = _firstSeen.Observe(record.Source, record.HttpHost ?? "", record.Id,
                context.TimestampUtc, TimeSpan.FromHours(24), distinctTargets: true);
            if (seen != 1) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "cleartext_http,multipart_request,first_observed_instance_domain", "rule"),
                new("http.transfer_status", "multipart_body_unobserved", "rule")
            };
            evidence.AddRange(AnalystContext("A multipart request shape targeted a first-observed external domain in this detector instance.",
                "Instance-first observation is not approved-baseline novelty or domain registration age; multipart content is unobserved.",
                "Legitimate new vendor portals may match.",
                "Verify domain approval, endpoint process and upload body with independent evidence."));
            return MatchExfiltration(context, SeverityLevel.High,
                "Multipart request to first-observed external domain", "MultipartUnknownDomainUpload", evidence,
                c => { c.AddEvidence(0.26, "multipart-request"); c.AddEvidence(0.24, "first-observed-instance-domain"); c.AddEvidence(0.14, "external-destination"); },
                cooldownKey: record.Source + ":" + record.Destination + ":multipart");

        }
    }
}
