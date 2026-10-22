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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var support = LooksLikeArchiveTransfer(record) || LooksLikeSensitiveFileTransfer(record) || IsUploadLike(record) || IsLikelyAutomationProcess(record) || IsUnknownExternalDomain(record, context, TimeSpan.FromHours(24));
            if (!IsOffHours(context.TimestampUtc) || !IsLargeOutboundTransfer(record, 250 * 1024 * 1024) || !support || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "off_hours,bulk_egress,supporting_exfil_indicator")) { new("rule.localTimeBucket", "off_hours_or_weekend_utc", "rule") };
            evidence.AddRange(AnalystContext("A bulk outbound transfer happened during off-hours/weekend with additional exfil-supporting evidence.", "Severity is Medium because time alone is weak, but bulk transfer plus exfil indicators is actionable.", "Scheduled updates/backups can match. Tune known jobs before using this as a paging alert.", "Check whether the source has an approved off-hours transfer schedule.", "Correlate with staging, credential, and upload rules."));
            return MatchExfiltration(context, SeverityLevel.Medium, "Off-hours bulk egress with supporting indicator", "OffHoursBulkEgress", evidence, c => { c.AddEvidence(0.20, "off-hours"); c.AddEvidence(0.24, "bulk-egress"); c.AddEvidence(0.18, "supporting-exfil-indicator"); }, window: TimeSpan.FromHours(1), cooldownKey: CooldownIdentity(record, "offhours-bulk"));
        }
    }
}
