// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R255_OffHoursBulkEgressIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R255_OffHoursBulkEgressIndicatorRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R255", "Off-Hours Bulk Egress Indicator", "ExfiltrationAdvanced", "Detects bulk outbound transfer during off-hours only when additional exfil indicators are present.", SeverityLevel.Medium, "Rules.R255.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R255", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process }, new[] { "source", "external_destination", "off_hours", "bulk_bytes", "supporting_indicator" }, new[] { "flow.bytes", "rule.localTimeBucket", "matched_conditions" }, new[] { "Transfer must occur during off-hours/weekend.", "Outbound volume must be bulk-sized.", "Archive, sensitive file, upload, automation, or unknown-domain support must be present." }, new[] { "Do not alert on scheduled approved backups.", "Do not alert on off-hours browsing alone." }, 78, 1, TimeSpan.FromHours(1), TimeSpan.FromMinutes(45), "source+destination+offhours", new[] { "Scheduled backups and software updates often run off-hours." }, new[] { "Mode", "BusinessHours", "BulkBytes", "ApprovedBackupJobs" }, new[] { "positive off-hours bulk upload sample", "negative approved off-hours backup sample" });
        public R255_OffHoursBulkEgressIndicatorRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch251255Evidence.OffHoursDeclared(record, context.TimestampUtc, out var declared)
                || IsLikelyApprovedSyncOrBackup(record)
                || !NetworkBatch251255Evidence.AutomationProcess(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "utc_off_hours,large_declared_http_body,automation_process", "rule"),
                new("http.declaredBodyBytes", declared.ToString(System.Globalization.CultureInfo.InvariantCulture), "http"),
                new("rule.timeBasis", "utc_heuristic_not_local_business_hours", "rule")
            };
            evidence.AddRange(AnalystContext("An automated cleartext HTTP upload request during UTC off-hours declared a large body.",
                "UTC is not the asset's local business schedule; Content-Length is not delivered volume.",
                "Approved maintenance and backups may resemble this request.",
                "Check asset timezone, approvals and measured transfer bytes."));
            return MatchExfiltration(context, SeverityLevel.Medium,
                "Off-hours large declared HTTP upload request", "OffHoursBulkEgress", evidence,
                c => { c.AddEvidence(0.20, "utc-off-hours"); c.AddEvidence(0.24, "declared-large-body"); c.AddEvidence(0.18, "automation-process"); },
                window: TimeSpan.FromHours(1),
                cooldownKey: record.Source + ":" + record.Destination + ":offhours");

        }
    }
}
