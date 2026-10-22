// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R115_MQTTHighFrequencyPublishBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R115_MQTTHighFrequencyPublishBurstRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R115",
            Name: "MQTT High-Frequency Publish Burst",
            Category: "IotOt",
            Description: "Detects unusually high-frequency MQTT publish bursts, with stronger gating for internal brokers so ordinary sensor chatter does not alert by default.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R115.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R115",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "mqtt.distinctTopics", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain MQTT publish context.",
                "The source must exceed a strong publish-rate threshold within the configured window.",
                "Internal broker traffic should require more burst evidence than public or external broker traffic."
            },
            negativeConditions: new[]
            {
                "Do not alert on mqtt mentions without publish context.",
                "Do not alert on moderate internal sensor publish rates.",
                "Do not alert on low-volume single-topic chatter."
            },
            minimumConfidence: 74,
            threshold: 90,
            window: TimeSpan.FromMinutes(1),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "High-rate telemetry bursts during outages, reconnect storms, or broker recovery can look similar."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "ElevatedThreshold", "WindowSeconds", "DistinctTopicThreshold" },
            requiredTests: new[]
            {
                "positive external mqtt publish burst sample",
                "negative moderate internal publish burst sample",
                "negative non-publish mqtt sample"
            });

        public R115_MQTTHighFrequencyPublishBurstRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var text = Text(record);
            if (!IsMqtt(record)
                || text.IndexOf("publish", StringComparison.OrdinalIgnoreCase) < 0
                   && text.IndexOf("pubrel", StringComparison.OrdinalIgnoreCase) < 0
                   && text.IndexOf("puback", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return NoMatch();
            }

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 60, 10, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 90, 10, 5000);
            var elevatedThreshold = IntSetting(Descriptor.RuleId, "ElevatedThreshold", 180, threshold, 10000);
            var distinctTopicThreshold = IntSetting(Descriptor.RuleId, "DistinctTopicThreshold", 8, 1, 500);
            var host = BestHost(record);
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{record.Destination}:{host}", context.TimestampUtc, window);
            var topic = NormalizeTopic(ExtractTopic(text));
            var distinctTopics = string.IsNullOrWhiteSpace(topic)
                ? 0
                : CountDistinctValues($"{Descriptor.RuleId}:topics:{record.Source}:{record.Destination}:{host}", topic, context.TimestampUtc, window);
            var externalOrPublicBroker = IsExternalAddress(record.Destination) || IsPublicMqttBroker(host);
            if (count < threshold)
                return NoMatch();

            if (!externalOrPublicBroker && count < elevatedThreshold && distinctTopics < distinctTopicThreshold)
                return NoMatch();

            var highSeverity = externalOrPublicBroker || count >= elevatedThreshold || distinctTopics >= distinctTopicThreshold * 2;
            var matchedConditions = new List<string> { "mqtt_publish_context", "burst_threshold" };
            if (externalOrPublicBroker) matchedConditions.Add("external_or_public_broker");
            if (distinctTopics >= distinctTopicThreshold) matchedConditions.Add("multi_topic_publish_burst");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("mqtt.distinctTopics", distinctTopics.ToString(System.Globalization.CultureInfo.InvariantCulture), "iot-ot"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                $"{record.Source} emitted {count} MQTT publish-related events within {window.TotalSeconds:F0}s.",
                highSeverity
                    ? "Severity is High because the publish burst hit an external or public broker path or otherwise exceeded the elevated burst threshold."
                    : "Severity is Medium because the publish rate is unusually high, but the broker context is more consistent with an internal deployment.",
                "Reconnect storms, telemetry backlog flushes, or broker failover can create short-lived publish bursts.",
                "Validate whether the broker was in recovery or whether a device reconnect storm occurred.",
                "Correlate the burst with broker health and device lifecycle telemetry."));

            return MatchIot(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"MQTT high-frequency publish burst from {record.Source}",
                "MQTT",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "mqtt-publish-context");
                    confidence.AddEvidence(0.20, "burst-threshold");
                    if (externalOrPublicBroker) confidence.AddCorrelation(0.14, "external-or-public-broker");
                    if (count >= elevatedThreshold) confidence.AddEvidence(0.10, "elevated-burst-threshold");
                    if (distinctTopics >= distinctTopicThreshold) confidence.AddEvidence(0.08, "multi-topic-burst");
                },
                count: count,
                window: window,
                cooldownKey: $"{record.Source}:{record.Destination}:{host}");
        }
    }
}
