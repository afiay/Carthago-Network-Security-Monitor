// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R213_CloudStoragePresignedUrlMassAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R213_CloudStoragePresignedUrlMassAccessRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R213",
            Name: "Cloud Storage Presigned URL Mass Access",
            Category: "CloudDev",
            Description: "Detects bursts of provider-specific presigned URL access against cloud storage, instead of matching any generic signature parameter text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R213.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R213",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target a cloud-storage host with concrete AWS, GCS, or Azure signed-URL parameters.",
                "The same source must access many signed URLs in a short window."
            },
            negativeConditions: new[]
            {
                "Do not alert on single or low-volume signed URL access.",
                "Do not alert on generic query-string signatures outside cloud storage contexts."
            },
            minimumConfidence: 82,
            threshold: 8,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider+uri",
            falsePositives: new[] { "Bulk data transfer workflows and approved backup tools can legitimately use many presigned URLs." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive mass presigned url sample", "negative single presigned url sample" });

        public R213_CloudStoragePresignedUrlMassAccessRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch206215Evidence.Presigned(context.Record, out var provider, out var artifact))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 200);
            if (!_observations.Observe(context.Record,
                    $"{Descriptor.RuleId}:{context.Record.Source}:{provider}", artifact,
                    context.TimestampUtc, window, 0, out var count, out _))
                return NoMatch();
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", provider, "cloud"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "cloud_storage_signed_url,distinct_url_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source accessed many provider-specific cloud-storage signed URLs in a short window.",
                "Severity is High because bulk signed-URL use can indicate large ad hoc transfer, staged exfiltration, or temporary-credential abuse.",
                "Backup tooling, artifact distribution, and sanctioned bulk transfer workflows can legitimately generate signed URL bursts.",
                "Review the calling process and destination object set accessed through the signed URLs.",
                "Confirm whether the signed-URL transfer volume is approved for the source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Mass cloud-storage presigned URL access observed",
                "CloudStoragePresignedUrlMassAccess",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "cloud-storage-signed-url");
                    confidence.AddEvidence(0.20, "distinct-url-threshold");
                    if (!IsBrowserLikeUserAgent(context.Record) && !string.IsNullOrWhiteSpace(context.Record.ProcessName)) confidence.AddCorrelation(0.08, "non-browser-process");
                },
                count,
                window,
                $"{context.Record.Source}:{provider}");
        }
    }
}
