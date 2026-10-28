// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R216_GoogleStorageBucketEnumerationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R216_GoogleStorageBucketEnumerationRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R216",
            Name: "Google Storage Bucket Enumeration",
            Category: "CloudDev",
            Description: "Detects concrete Google Cloud Storage listing semantics instead of broad storage.googleapis.com text matches.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R216.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R216",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must target Google Cloud Storage and use JSON or XML object-listing semantics.",
                "Media-download style object fetches should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on alt=media object downloads.",
                "Do not alert on unrelated googleapis.com traffic."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+path",
            falsePositives: new[] { "Legitimate inventory, synchronization, and backup workflows can enumerate Google Cloud Storage objects intentionally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive gcs bucket listing sample", "negative gcs object download sample" });

        public R216_GoogleStorageBucketEnumerationRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch216220Evidence.GcsList(record) || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem>
            {
                new("cloud.provider", "google-cloud-storage", "cloud"),
                new("matched_conditions", "typed_http,gcs_exact_host,bucket_listing_request", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A parsed HTTP GET targeted a GCS JSON or XML bucket-listing request shape.",
                "Listing requests can indicate object discovery, but neither response nor authorization success is established.",
                "Approved backup and inventory clients also list buckets.",
                "Correlate the request with authorized inventory activity.",
                "Confirm bucket access against independently sourced cloud audit logs."));
            return MatchHttpApi(context, SeverityLevel.Medium,
                "Google Cloud Storage bucket-listing request observed",
                "GoogleStorageBucketEnumeration", evidence, confidence =>
                {
                    confidence.AddEvidence(0.22, "gcs-host");
                    confidence.AddEvidence(0.20, "listing-semantics");
                }, cooldownKey: NetworkBatch216220Evidence.SafeKey(record));
        }
    }
}

