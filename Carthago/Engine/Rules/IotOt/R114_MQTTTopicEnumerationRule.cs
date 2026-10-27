// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R114_MQTTTopicEnumerationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R114_MQTTTopicEnumerationRule : IotOtPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch081085Dedup _seen = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R114",
            Name: "MQTT Topic Enumeration",
            Category: "IotOt",
            Description: "Detects MQTT wildcard subscriptions or unusually broad topic-subscription sweeps from a single source, rather than treating generic mqtt text as enumeration.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R114.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R114",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "iot_or_ot_context" },
            evidenceFields: new[] { "mqtt.topic", "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain MQTT subscription or topic-discovery context.",
                "Wildcard subscriptions or high unique-topic counts should drive detection.",
                "Publish-only traffic should not satisfy the rule."
            },
            negativeConditions: new[]
            {
                "Do not alert on mqtt mentions without subscribe or topic context.",
                "Do not alert on normal publish traffic.",
                "Do not alert on small topic sets under threshold."
            },
            minimumConfidence: 72,
            threshold: 20,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+topic",
            falsePositives: new[]
            {
                "Legitimate inventory or broker-management tooling can enumerate topics during maintenance windows."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive wildcard mqtt topic sample",
                "positive unique topic sweep sample",
                "negative publish-only mqtt sample"
            });

        public R114_MQTTTopicEnumerationRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch111115Evidence.Mqtt(context)
                || !NetworkBatch111115Evidence.TryAction(record, "subscribe", out var topic)
                || !_seen.First(record.Id, context.TimestampUtc))
                return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 20, 5, 500);
            var wildcard = NetworkBatch111115Evidence.Wildcard(topic);

            if (wildcard)
            {
                var evidence = new List<DetectionEvidenceItem>
                {
                    new("mqtt.topic", "[redacted]", "iot-ot"),
                    new("mqtt.topicKind", "wildcard", "iot-ot"),
                    new("matched_conditions", "wildcard_subscription,topic_discovery_context", "rule")
                };
                evidence.AddRange(AnalystContext(
                    "The source issued an MQTT wildcard topic subscription, which is consistent with broad topic enumeration.",
                    "Severity is High because wildcard MQTT subscriptions can expose the full topic namespace quickly.",
                    "Broker-management tooling can use wildcard subscriptions during maintenance.",
                    "Validate whether the source is an approved broker-management or inventory tool.",
                    "Review the broker, topic scope, and follow-on subscriptions from the same source."));

                return MatchIot(
                    context,
                    SeverityLevel.High,
                    "MQTT wildcard topic enumeration",
                    "MQTT",
                    evidence,
                    confidence =>
                    {
                        confidence.AddEvidence(0.38, "wildcard-subscription");
                        confidence.AddEvidence(0.20, "topic-discovery-context");
                    },
                    cooldownKey: $"{record.Source}:{record.Destination}");
            }

            if (string.IsNullOrWhiteSpace(topic))
                return NoMatch();

            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}:{record.Destination}",
                NetworkBatch111115Evidence.TopicFingerprint(topic), context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "distinct_topic_threshold", "topic_discovery_context" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("mqtt.topic", "[redacted]", "iot-ot"),
                new("mqtt.topicKind", "exact", "iot-ot"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                $"{record.Source} touched {count} distinct MQTT topics within {window.TotalMinutes:F0} minutes.",
                "Severity is Medium because the source enumerated an unusually broad MQTT topic set without using a blanket wildcard.",
                "Legitimate inventory or broker-inspection workflows can enumerate many topics during change windows.",
                "Review whether the source is expected to inventory or administer MQTT brokers.",
                "Correlate the enumerated topics with follow-on subscriptions or publishes from the same source."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                $"MQTT topic enumeration from {record.Source}",
                "MQTT",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "distinct-topic-threshold");
                    confidence.AddEvidence(0.18, "topic-discovery-context");
                    if (count >= threshold * 2) confidence.AddEvidence(0.10, "broad-topic-sweep");
                },
                count: count,
                window: window,
                cooldownKey: $"{record.Source}");
        }
    }
}
