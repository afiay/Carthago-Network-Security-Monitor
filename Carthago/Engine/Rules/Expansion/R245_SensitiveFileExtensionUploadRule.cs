// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R245_SensitiveFileExtensionUploadRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R245_SensitiveFileExtensionUploadRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R245", "Sensitive File Extension Upload", "ExfiltrationAdvanced", "Detects external upload of files whose name, extension, or metadata indicates credentials, keys, secrets, or sensitive exports.", SeverityLevel.High, "Rules.R245.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R245", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload }, new[] { "source", "destination_or_host", "upload_semantics", "sensitive_filename_or_content" }, new[] { "file_or_path.indicator", "http.method", "matched_conditions" }, new[] { "Traffic must be an external upload-like request.", "Observed name/path/content must indicate credentials, keys, secrets, or sensitive exports.", "Approved sync/backup processes are suppressed." }, new[] { "Do not alert on downloads.", "Do not alert on generic .json or .csv without sensitive-name/content indicators." }, 83, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), "source+destination+sensitive-file", new[] { "Password-manager backups and approved secret vault exports may be legitimate but should be rare." }, new[] { "Mode", "SensitiveExtensions", "SensitiveNameIndicators", "ApprovedDestinations" }, new[] { "positive external pem upload sample", "negative normal json API post sample" });
        public R245_SensitiveFileExtensionUploadRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch241245Evidence.Sensitive(r) || IsLikelyApprovedSyncOrBackup(r)
                || !_replay.Observe(r, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "external_http,sensitive_file_name,declared_body", "rule"),
                new("http.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A cleartext HTTP upload request included a risk-relevant filename.",
                "Request metadata alone cannot prove payload transmission or successful exfiltration.",
                "Approved business exports and backup workflows can resemble this request.",
                "Review source, destination authorization and independent transfer evidence."));
            return MatchExfiltration(context, SeverityLevel.High, "Sensitive filename upload request observed", "SensitiveFileUpload",
                evidence, c => { c.AddEvidence(0.28,"sensitive-filename"); c.AddEvidence(0.22,"external-upload-request"); c.AddEvidence(0.14,"unapproved-client"); },
                cooldownKey: r.Source + ":" + r.Destination + ":SensitiveFileUpload");
        }

    }
}
