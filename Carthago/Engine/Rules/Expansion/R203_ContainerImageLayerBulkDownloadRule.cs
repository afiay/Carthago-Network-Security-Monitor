// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R203_ContainerImageLayerBulkDownloadRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R203_ContainerImageLayerBulkDownloadRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R203",
            Name: "Container Image Layer Bulk Download",
            Category: "CloudDev",
            Description: "Detects bursts of distinct container layer downloads from first-seen non-official registries, instead of any blob or digest text.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R203.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R203",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "count", "flow.bytes", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must be a Docker Registry blob pull with a concrete layer digest.",
                "The registry should be external and not an official public registry.",
                "The same source should download many distinct layers in a short window with meaningful byte volume."
            },
            negativeConditions: new[]
            {
                "Do not alert on single or low-volume layer pulls.",
                "Do not alert on official public registries."
            },
            minimumConfidence: 76,
            threshold: 6,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+digest",
            falsePositives: new[] { "Legitimate CI pipelines can bulk-pull layers from newly introduced registries." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "MinimumBytes" },
            requiredTests: new[] { "positive bulk layer pull sample", "negative single layer pull sample" });

        public R203_ContainerImageLayerBulkDownloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!TryClassifyDockerRegistryOperation(record, out var operation, out var artifactKey) || !string.Equals(operation, "pull", StringComparison.OrdinalIgnoreCase))
                return NoMatch();

            var host = BestHost(record);
            if (IsOfficialContainerRegistryHost(host) || !artifactKey.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.container-layer-host", record.Source ?? "unknown", host, context, "operation=pull");
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 6, 3, 100);
            var minimumBytes = IntSetting(Descriptor.RuleId, "MinimumBytes", 1_500_000, 100_000, 200_000_000);
            var firstSeen = baseline.IsFirstSeen
                || (baseline.FirstSeenUtc.HasValue && context.TimestampUtc - baseline.FirstSeenUtc.Value <= window)
                || (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                    && FirstSeenWithinWindow($"{Descriptor.RuleId}:first-seen:{record.Source}:{host}", context.TimestampUtc, window));
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}:{host}", artifactKey, context.TimestampUtc, window);
            var bytes = AddBytesWindow($"{Descriptor.RuleId}:bytes:{record.Source}:{host}", context.TimestampUtc, TransferBytes(record), window);
            if (!firstSeen || count < threshold || bytes < minimumBytes)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("flow.bytes", bytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"),
                new("matched_conditions", "container_layer_pull,unofficial_registry,first_seen_host,bulk_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source downloaded many distinct container image layers with meaningful byte volume from a first-seen non-official registry.",
                "Severity is Medium because bulk layer pulls to unfamiliar registries can indicate image staging, container artifact exfiltration, or shadow supply-chain activity.",
                "Legitimate CI or ephemeral build systems can bulk-pull layers from new registries. Validate the registry owner and workload context before escalating.",
                "Review the calling process and repository names associated with the layer downloads.",
                "Confirm whether the registry host is approved for the environment."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Bulk container layer download observed",
                "ContainerLayerBulkDownload",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "container-layer-pull");
                    confidence.AddEvidence(0.16, "unofficial-registry");
                    confidence.AddEvidence(0.12, "first-seen-host");
                    confidence.AddEvidence(0.14, "bulk-threshold");
                },
                count,
                window,
                $"{record.Source}:{host}");
        }
    }
}
