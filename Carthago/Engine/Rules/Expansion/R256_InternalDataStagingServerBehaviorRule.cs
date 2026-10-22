// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R256_InternalDataStagingServerBehaviorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R256_InternalDataStagingServerBehaviorRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R256", "Internal Data Staging Server Behavior", "ExfiltrationAdvanced", "Detects internal host-to-host staging behavior when archive/dump/sensitive indicators and repeated collection volume are visible.", SeverityLevel.High, "Rules.R256.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R256", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.Process }, new[] { "internal_source", "internal_destination", "staging_indicator", "volume_or_repetition" }, new[] { "file_or_path.indicator", "flow.bytes", "rule.windowCount", "matched_conditions" }, new[] { "Both endpoints must be internal.", "Traffic must include staging/archive/dump/sensitive indicators.", "Repeated collection or meaningful volume must be present." }, new[] { "Do not alert on normal SMB file-share use without staging indicators.", "Do not alert on approved backup collectors." }, 80, 6, TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(45), "source+destination+staging", new[] { "Patch distribution, backup collection, and build artifact movement can match." }, new[] { "Mode", "ApprovedBackupCollectors", "WindowCount", "MinimumBytes" }, new[] { "positive internal staging sample", "negative normal file share sample" });
        public R256_InternalDataStagingServerBehaviorRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasInternalStagingIndicators(record) || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var key = $"R256:{record.Source}:{record.Destination}";
            var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(30));
            var bytes = AddBytesWindow($"R256B:{record.Source}:{record.Destination}", context.TimestampUtc, TransferBytes(record), TimeSpan.FromMinutes(30));
            if (count < 6 && bytes < 250 * 1024 * 1024) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "internal_staging_indicator,repeated_or_bulk_collection")) { new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"), new("flow.windowBytes", bytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "flow") };
            evidence.AddRange(AnalystContext("Internal host-to-host transfer behavior looked like collection/staging before possible exfiltration.", "Severity is High because staging often precedes external exfiltration even before the final egress is visible.", "Approved backup/build artifact collectors can match; tune them by source/destination role.", "Check whether the destination normally receives data from many systems.", "Look for a later external transfer from the staging destination."));
            return MatchExfiltration(context, SeverityLevel.High, "Internal data staging behavior", "InternalDataStaging", evidence, c => { c.AddEvidence(0.24, "staging-indicators"); c.AddEvidence(0.20, "repeated-or-bulk-collection"); c.AddEvidence(0.12, "internal-collection-path"); }, count: count, window: TimeSpan.FromMinutes(30), cooldownKey: $"{record.Source}:{record.Destination}:internal-staging");
        }
    }
}
