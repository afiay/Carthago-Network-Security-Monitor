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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !IsUploadLike(record) || !LooksLikeSourceCodeArchiveTransfer(record) || (LooksLikeGitClient(record) && IsOfficialGitHost(BestHost(record)))) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "external_upload,archive_indicator,source_code_indicator"));
            evidence.AddRange(AnalystContext("An external upload looked like a compressed source-code or repository artifact.", "Severity is High because source-code theft can expose intellectual property, secrets, and architecture details.", "Approved CI release publishing can match. Tune CI runner identities and sanctioned artifact destinations.", "Verify whether the destination is an approved source-control or artifact system.", "Check whether secrets or environment files were included in the archive."));
            return MatchExfiltration(context, SeverityLevel.High, "Source-code archive uploaded externally", "SourceCodeArchiveUpload", evidence, c => { c.AddEvidence(0.26, "source-code-indicator"); c.AddEvidence(0.22, "archive-upload"); c.AddEvidence(0.14, "non-standard-git-destination"); }, cooldownKey: CooldownIdentity(record, "source-archive"));
        }
    }
}
