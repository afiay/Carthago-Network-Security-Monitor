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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !IsUploadLike(record) || !LooksLikeSensitiveFileTransfer(record) || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "external_upload,sensitive_file_indicator,unapproved_client"));
            evidence.AddRange(AnalystContext("An external upload contained file/path/content indicators for secrets, keys, credentials, or sensitive exports.", "Severity is High because a single key, token, or password vault can enable follow-on compromise.", "Approved vault backup workflows may match; tune them narrowly by process and destination.", "Identify the exact file or payload indicator.", "Rotate exposed keys/tokens if the transfer is unauthorized.", "Review the source host for credential harvesting activity."));
            return MatchExfiltration(context, SeverityLevel.High, "Sensitive file indicator uploaded externally", "SensitiveFileUpload", evidence, c => { c.AddEvidence(0.28, "sensitive-file-indicator"); c.AddEvidence(0.22, "external-upload"); c.AddEvidence(0.14, "unapproved-client"); }, cooldownKey: CooldownIdentity(record, "sensitive-upload"));
        }
    }
}
