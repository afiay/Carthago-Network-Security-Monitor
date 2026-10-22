// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R248_FtpUploadToExternalHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R248_FtpUploadToExternalHostRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R248", "FTP Upload To External Host", "ExfiltrationAdvanced", "Detects FTP upload semantics from an internal source to an external host, not merely any FTP control connection.", SeverityLevel.High, "Rules.R248.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R248", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.Process }, new[] { "source", "external_destination", "ftp_context", "upload_semantics" }, new[] { "network.destinationPort", "process.name", "matched_conditions" }, new[] { "Traffic must be internal-to-external.", "FTP context must be present.", "Upload command or upload metadata must be present." }, new[] { "Do not alert on FTP downloads or server banners.", "Do not alert on internal FTP transfers." }, 82, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), "source+destination+ftp", new[] { "Legacy approved FTP integrations may match and should be explicitly allowlisted." }, new[] { "Mode", "ApprovedFtpServers", "CooldownSeconds" }, new[] { "positive FTP STOR sample", "negative FTP LIST/download sample" });
        public R248_FtpUploadToExternalHostRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !IsFtpUploadContext(record) || !(IsUploadLike(record) || ContainsAny(Text(record), "STOR ", "APPE "))) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "ftp_context,upload_semantics,external_destination"));
            evidence.AddRange(AnalystContext("FTP upload semantics were observed from an internal host to an external server.", "Severity is High because FTP is often unencrypted and is a common legacy path for data exfiltration.", "Legacy business transfers can be legitimate; use explicit approved FTP server lists.", "Validate whether the external FTP host is approved.", "Inspect transferred filenames and credentials used for the session."));
            return MatchExfiltration(context, SeverityLevel.High, "FTP upload to external host", "FtpExternalUpload", evidence, c => { c.AddEvidence(0.30, "ftp-upload-semantics"); c.AddEvidence(0.22, "external-destination"); c.AddEvidence(0.10, "legacy-cleartext-risk"); }, cooldownKey: CooldownIdentity(record, "ftp-upload"));
        }
    }
}
