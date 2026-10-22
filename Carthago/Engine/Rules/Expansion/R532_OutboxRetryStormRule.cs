// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R532_OutboxRetryStormRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R532_OutboxRetryStormRule : PlatformHealthAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R532",
            Name: "Outbox Retry Storm",
            Category: "PlatformHealthAdvanced",
            Description: "Detects a concrete Carthago outbox retry storm only when platform-health telemetry explicitly references outbox retry/backoff/failure behavior; ordinary network retries do not match.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R532.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreatePlatformHealthProfile(
            ruleId: "R532",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "platform_health_event", "component", "retry_signal" },
            evidenceFields: new[] { "platform.component", "matched_conditions", "event.info" },
            positiveConditions: new[]
            {
                "The event must be explicit platform-health telemetry.",
                "The event must reference the outbox component.",
                "The event must include retry, backoff, failure, or storm semantics."
            },
            negativeConditions: new[]
            {
                "Do not alert on TCP retransmission, HTTP retry, or generic network failures without outbox context.",
                "Do not alert from packet-only telemetry with no platform-health anchor."
            },
            minimumConfidence: 86,
            threshold: 5,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "component+site",
            falsePositives: new[] { "Planned sink maintenance can cause temporary outbox retries; tune maintenance windows instead of weakening the rule." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive outbox retry storm platform health event", "negative ordinary http retry packet" });

        public R532_OutboxRetryStormRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            if (!IsPlatformHealthRecord(record) || !ContainsAny(text, "outbox") || !ContainsAny(text, "retry", "retries", "backoff", "deadletter", "dead-letter"))
                return NoMatch();

            var hasStormSignal = ContainsAny(text, "storm", "spike", "burst", "excessive", "saturated", "queue depth", "queue-depth", "failed", "failure", "sink unavailable");
            var key = $"{Descriptor.RuleId}:{MetricKey(record)}:{record.Source}";
            var count = CountWindowEvents(key, context.TimestampUtc, TimeSpan.FromMinutes(5));
            if (!hasStormSignal && count < 5)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", hasStormSignal ? "platform_health,outbox,retry,storm_signal" : "platform_health,outbox,retry,window_threshold", "rule"),
                new("platform.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "platform-health")
            };
            evidence.AddRange(AnalystContext(
                "The detection pipeline reported repeated outbox retry/backoff behavior, indicating that confirmed detections may not be reaching a downstream sink cleanly.",
                "Severity is High because delivery instability can delay incident visibility even when detections are produced correctly.",
                "Maintenance, sink outage, or deliberate offline testing can produce legitimate retry storms.",
                "Check sink availability and credentials.",
                "Verify that detection events are still persisted locally before outbound delivery is retried.",
                "Inspect queue depth and dead-letter records before clearing the condition."));

            return MatchPlatformHealth(
                context,
                SeverityLevel.High,
                "Outbox retry storm reported by platform health telemetry",
                "OutboxRetryStorm",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "platform-health-anchor");
                    confidence.AddEvidence(0.26, "outbox-component");
                    confidence.AddEvidence(0.22, "retry-semantics");
                    if (hasStormSignal) confidence.AddEvidence(0.18, "explicit-storm-signal");
                    else confidence.AddCorrelation(0.12, "retry-threshold-window");
                },
                count,
                TimeSpan.FromMinutes(5),
                cooldownKey: key);
        }
    }
}
