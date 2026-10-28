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
        private readonly NetworkBatch256260Evidence.BoundedWindow _window = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch256260Evidence.InternalStagingRequest(r)) return NoMatch();
            var count = _window.Observe(r, context.TimestampUtc, r.Source + "|" + r.Destination, TimeSpan.FromMinutes(30));
            if (count < 6) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "internal_cleartext_http_archive_named_request,repeated_distinct_requests", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.bodyStatus", "declared_not_transferred", "http")
            };
            evidence.AddRange(AnalystContext("Six distinct archive/dump-named internal HTTP upload requests were observed.",
                "Request repetition is staging-like, but does not prove storage or successful transfer.",
                "Approved backups and build-artifact collection require explicit exclusions.",
                "Corroborate destination role and endpoint file events."));
            return MatchExfiltration(context, SeverityLevel.High, "Repeated internal archive-named HTTP upload requests",
                "InternalDataStaging", evidence,
                c => { c.AddEvidence(0.24, "typed-internal-http"); c.AddEvidence(0.20, "distinct-requests"); c.AddEvidence(0.12, "archive-named-path"); },
                count: count, window: TimeSpan.FromMinutes(30), cooldownKey: r.Source + ":" + r.Destination + ":staging-request");
        }
    }
}
