// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R202_DockerRegistryPushPullAnomalyRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R202_DockerRegistryPushPullAnomalyRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R202",
            Name: "Docker Registry Push Pull Anomaly",
            Category: "CloudDev",
            Description: "Detects repeated Docker Registry API push or pull operations against first-seen non-official external registries, rather than any /v2/ path mention.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R202.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R202",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "count", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must be a concrete Docker Registry v2 push or pull operation.",
                "The destination registry should be external and not an official public registry.",
                "The same source should repeat distinct registry operations within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on official public registries.",
                "Do not alert on isolated or non-registry /v2/ traffic."
            },
            minimumConfidence: 76,
            threshold: 6,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host+artifact",
            falsePositives: new[] { "Self-hosted enterprise registries and CI runners can legitimately push or pull images to newly onboarded external registries." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive repeated custom registry activity sample", "negative official registry sample" });

        public R202_DockerRegistryPushPullAnomalyRule() : base(Rule, Profile) { }

        private readonly NetworkBatch201205Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch201205Evidence.Registry(record, out var operation, out var artifactKey))
                return NoMatch();

            var host = BestHost(record);
            if (IsOfficialContainerRegistryHost(host) || IsBrowserLikeUserAgent(record))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.docker-registry-host", record.Source ?? "unknown", host, context, $"operation={operation}");
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 6, 3, 100);
            var firstSeen = baseline.IsFirstSeen
                || (baseline.FirstSeenUtc.HasValue && context.TimestampUtc - baseline.FirstSeenUtc.Value <= window)
                || (string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)
                    && FirstSeenWithinWindow($"{Descriptor.RuleId}:first-seen:{record.Source}:{host}", context.TimestampUtc, window));
            if (!_window.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{host}", artifactKey,
                context.TimestampUtc, window, 0, out var count, out _))
                return NoMatch();
            if (count < threshold || !firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("cloud.operation", operation, "cloud"),
                new("matched_conditions", "docker_registry_operation,unofficial_registry,first_seen_host,threshold_reached", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source repeatedly performed Docker Registry API operations against a first-seen non-official external registry.",
                "Severity is Medium because repeated registry interactions to an unfamiliar external host can indicate image exfiltration, staging, or supply-chain activity.",
                "Newly onboarded enterprise registries or CI workflows can look similar. Validate the registry owner and pipeline context before escalating.",
                "Review the calling process and repository names involved in the push or pull sequence.",
                "Confirm whether the external registry host is approved for the workload."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Repeated non-official Docker registry activity observed",
                "DockerRegistryAnomaly",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "docker-registry-operation");
                    confidence.AddEvidence(0.16, "unofficial-registry");
                    confidence.AddEvidence(0.12, "first-seen-host");
                    confidence.AddEvidence(0.14, "threshold-reached");
                },
                count,
                window,
                $"{record.Source}:{host}:{operation}");
        }
    }
}
