// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R254_RepeatedSmallChunkUploadsRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R254_RepeatedSmallChunkUploadsRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R254", "Repeated Small Chunk Uploads", "ExfiltrationAdvanced", "Detects repeated small outbound upload chunks to the same external target within a short window.", SeverityLevel.High, "Rules.R254.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R254", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow }, new[] { "source", "external_destination", "upload_semantics", "repeated_small_chunks" }, new[] { "flow.bytes", "rule.windowCount", "matched_conditions" }, new[] { "Requests must be upload-like and outbound.", "Each request must be small enough to represent chunking.", "Count threshold must be reached for same source and destination." }, new[] { "Do not alert on single small telemetry posts.", "Do not alert on browser static requests." }, 82, 12, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(20), "source+destination+path", new[] { "Chunked legitimate uploads and backup clients can match." }, new[] { "Mode", "ChunkCount", "WindowSeconds", "SmallChunkMaxBytes", "ApprovedClients" }, new[] { "positive repeated chunks sample", "negative isolated telemetry post sample" });
        public R254_RepeatedSmallChunkUploadsRule() : base(Rule, Profile) { }
        private readonly NetworkBatch226230Evidence.Window _window = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch251255Evidence.Chunk(record, out var declared, out var pathKey)
                || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var count = _window.Observe(record.Source + "|" + record.Destination + "|" + pathKey,
                record.Destination ?? "", record.Id, context.TimestampUtc, TimeSpan.FromMinutes(5),
                distinctTargets: false);
            if (count < 12) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "parsed_http_upload,repeated_small_declared_body", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.declaredBodyBytes", declared.ToString(System.Globalization.CultureInfo.InvariantCulture), "http")
            };
            evidence.AddRange(AnalystContext("Repeated small declared HTTP upload requests targeted the same path.",
                "Repeated requests are not proven transferred chunks; packet IDs and declared lengths do not establish completion.",
                "Legitimate chunking APIs can match.",
                "Corroborate HTTP response and flow-delivery metrics."));
            return MatchExfiltration(context, SeverityLevel.High,
                "Repeated small declared HTTP upload requests", "RepeatedSmallChunkUploads", evidence,
                c => { c.AddEvidence(0.26, "repeated-small-requests"); c.AddEvidence(0.20, "upload-request"); c.AddEvidence(0.14, "external-destination"); },
                count: count, window: TimeSpan.FromMinutes(5),
                cooldownKey: record.Source + ":" + record.Destination + ":chunk");

        }
    }
}
