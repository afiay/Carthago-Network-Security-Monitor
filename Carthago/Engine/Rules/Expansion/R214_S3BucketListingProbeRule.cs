// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R214_S3BucketListingProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R214_S3BucketListingProbeRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R214",
            Name: "S3 Bucket Listing Probe",
            Category: "CloudDev",
            Description: "Detects concrete S3 bucket listing semantics such as list-type=2 or prefix enumeration instead of any S3 keyword match.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R214.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R214",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The host must be an Amazon S3 endpoint.",
                "The request must use explicit bucket-listing semantics such as list-type=2, prefix, or delimiter enumeration."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary object downloads.",
                "Do not alert on generic amazonaws host traffic without S3 listing semantics."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+path",
            falsePositives: new[] { "Legitimate inventory jobs, backup tools, or storage browsers can list S3 buckets intentionally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive s3 bucket listing sample", "negative s3 object download sample" });

        public R214_S3BucketListingProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!IsS3BucketListingRequest(context.Record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", "s3.amazonaws.com", "cloud"),
                new("matched_conditions", "s3_host,bucket_listing_semantics", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The HTTP request used concrete Amazon S3 bucket-listing semantics rather than downloading a specific object.",
                "Severity is Medium because bucket enumeration often reflects reconnaissance or broad data discovery activity.",
                "Inventory tooling, backup jobs, and approved storage browsers can list buckets legitimately.",
                "Review the calling process and bucket path being enumerated.",
                "Confirm whether the source is authorized to enumerate the target S3 bucket."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "S3 bucket listing probe observed",
                "S3BucketListing",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "s3-host");
                    confidence.AddEvidence(0.20, "bucket-listing-semantics");
                },
                cooldownKey: $"{context.Record.Source}:{BestHost(context.Record)}:{HttpPath(context.Record)}");
        }
    }
}
