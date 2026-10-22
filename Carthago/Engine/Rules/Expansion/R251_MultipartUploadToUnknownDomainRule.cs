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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var multipart = HeaderContains(record, "Content-Type", "multipart/form-data") || ContainsAny(Text(record), "multipart/form-data", "filename=", "content-disposition");
            if (!IsOutboundExternal(record) || !IsUploadMethod(record) || !multipart || !IsUnknownExternalDomain(record, context, TimeSpan.FromHours(24)) || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "multipart_upload,first_seen_external_domain,unapproved_root"));
            evidence.AddRange(AnalystContext("A multipart file-upload style request targeted a first-seen or unknown external domain.", "Severity is High because new upload domains are common in opportunistic exfiltration and throwaway infrastructure.", "New legitimate vendor portals can match; approve them by root domain after validation.", "Validate the root domain age, owner, and business purpose.", "Inspect uploaded filename/content-disposition metadata."));
            return MatchExfiltration(context, SeverityLevel.High, "Multipart upload to unknown external domain", "MultipartUnknownDomainUpload", evidence, c => { c.AddEvidence(0.26, "multipart-file-upload"); c.AddEvidence(0.24, "first-seen-domain"); c.AddEvidence(0.14, "external-destination"); }, cooldownKey: CooldownIdentity(record, "multipart-unknown"));
        }
    }
}
