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
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch246250Evidence.FtpUpload(record)
                || IsLikelyApprovedSyncOrBackup(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "parsed_ftp_stor_or_appe,external_destination", "rule"),
                new("ftp.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext("A captured FTP control request attempted STOR or APPE to an external server.",
                "A control command does not prove that data-channel bytes were delivered.",
                "Approved legacy FTP integrations may be legitimate.",
                "Corroborate server response and data-channel evidence."));
            return MatchExfiltration(context, SeverityLevel.High,
                "External FTP upload command observed", "FtpExternalUpload", evidence,
                c => { c.AddEvidence(0.30, "parsed-ftp-upload-command"); c.AddEvidence(0.22, "external-destination"); c.AddEvidence(0.10, "cleartext-control"); },
                cooldownKey: record.Source + ":" + record.Destination + ":ftp-upload");

        }
    }
}
