// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R244_DatabaseDumpFilenameTransferRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R244_DatabaseDumpFilenameTransferRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R244", "Database Dump Filename Transfer", "ExfiltrationAdvanced", "Detects outbound transfers whose observable name/path strongly resembles a database dump or backup artifact.", SeverityLevel.Critical, "Rules.R244.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R244", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload }, new[] { "source", "destination_or_host", "database_dump_indicator", "upload_or_large_transfer" }, new[] { "file_or_path.indicator", "flow.bytes", "matched_conditions" }, new[] { "Transfer must be outbound to an external target.", "Filename/path/content metadata must contain database-dump extension and dump/backup semantics.", "Either upload semantics or meaningful transfer volume must be present." }, new[] { "Do not alert on internal backup traffic.", "Do not alert on documentation or strings that only mention SQL without file-transfer context." }, 86, 1, TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(45), "source+destination+dbdump", new[] { "DBA exports to approved backup locations may be legitimate." }, new[] { "Mode", "MinimumBytes", "ApprovedDBABackupDestinations", "CooldownSeconds" }, new[] { "positive pg_dump upload sample", "negative internal DBA backup sample" });
        public R244_DatabaseDumpFilenameTransferRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch241245Evidence.DatabaseDump(r) || !_replay.Observe(r, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "external_http,database_dump_name,declared_body", "rule"),
                new("http.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A cleartext HTTP upload request included a risk-relevant filename.",
                "Request metadata alone cannot prove payload transmission or successful exfiltration.",
                "Approved business exports and backup workflows can resemble this request.",
                "Review source, destination authorization and independent transfer evidence."));
            return MatchExfiltration(context, SeverityLevel.Critical, "Database dump-named upload request observed", "DatabaseDumpEgress",
                evidence, c => { c.AddEvidence(0.30,"database-dump-name"); c.AddEvidence(0.22,"external-egress"); c.AddEvidence(0.16,"upload-request"); },
                cooldownKey: r.Source + ":" + r.Destination + ":DatabaseDumpEgress");
        }

    }
}
