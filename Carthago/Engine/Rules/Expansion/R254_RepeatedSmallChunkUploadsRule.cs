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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var bytes = TransferBytes(record);
            if (!IsOutboundExternal(record) || !IsUploadLike(record) || bytes <= 0 || bytes > 128 * 1024 || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var key = $"R254:{record.Source}:{BestHost(record)}:{record.DestinationPort}:{HttpPath(record)}";
            var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(5));
            if (count < 12) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "small_upload_chunk,repeated_window,external_destination")) { new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule") };
            evidence.AddRange(AnalystContext("The same internal source repeatedly sent small upload-like chunks to the same external target.", "Severity is High because chunked upload patterns can evade simple large-transfer thresholds.", "Legitimate chunked uploads exist; approve known sync/backup clients and SaaS destinations.", "Inspect whether chunks reconstruct into a larger transfer.", "Correlate with URI entropy or base64 blob indicators."));
            return MatchExfiltration(context, SeverityLevel.High, "Repeated small outbound upload chunks", "RepeatedSmallChunkUploads", evidence, c => { c.AddEvidence(0.26, "repeated-small-chunks"); c.AddEvidence(0.20, "upload-semantics"); c.AddEvidence(0.14, "external-destination"); }, count: count, window: TimeSpan.FromMinutes(5), cooldownKey: CooldownIdentity(record, "chunk-upload"));
        }
    }
}
