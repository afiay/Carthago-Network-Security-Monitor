// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R246_SourceCodeArchiveUploadRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R246_SourceCodeArchiveUploadRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R246", "Source Code Archive Upload", "ExfiltrationAdvanced", "Detects external upload of archive artifacts whose observable name/path suggests source code or repository content.", SeverityLevel.High, "Rules.R246.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R246", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.Process }, new[] { "source", "destination_or_host", "archive_indicator", "source_code_indicator", "upload_semantics" }, new[] { "file_or_path.indicator", "process.name", "matched_conditions" }, new[] { "External upload-like traffic must carry archive semantics.", "Name/path/content must indicate repository or source-code material.", "Known Git clients to official Git hosts are not sufficient alone." }, new[] { "Do not alert on normal git push/fetch to official repositories.", "Do not alert on ordinary CI package publishing without archive/source indicators." }, 82, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), "source+root_domain+source_archive", new[] { "Approved release uploads or CI artifacts can match." }, new[] { "Mode", "ApprovedGitHosts", "ApprovedCIRunners", "CooldownSeconds" }, new[] { "positive source zip upload sample", "negative normal git push sample" });
        public R246_SourceCodeArchiveUploadRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch246250Evidence.SourceArchive(record)
                || IsLikelyApprovedSyncOrBackup(record)
                || (LooksLikeGitClient(record) && IsOfficialGitHost(record.HttpHost))
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "cleartext_http,source_archive_filename,external_upload_request", "rule"),
                new("http.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext("An external cleartext HTTP upload request named a source archive.",
                "A filename and declared body do not prove the archive contents or completed transmission.",
                "Approved release publishing can resemble this request.",
                "Review authorization and independent transfer evidence."));
            return MatchExfiltration(context, SeverityLevel.High,
                "Source archive-named upload request observed", "SourceCodeArchiveUpload", evidence,
                c => { c.AddEvidence(0.26, "source-archive-name"); c.AddEvidence(0.22, "external-upload-request"); c.AddEvidence(0.14, "declared-body"); },
                cooldownKey: record.Source + ":" + record.Destination + ":source-archive");

        }
    }
}
