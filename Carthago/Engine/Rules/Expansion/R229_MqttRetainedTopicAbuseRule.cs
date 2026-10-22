// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R229_MqttRetainedTopicAbuseRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R229_MqttRetainedTopicAbuseRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R229",
            Name: "MQTT Retained Topic Abuse",
            Category: "IotOtAdvanced",
            Description: "Detects retained MQTT publishes only when they target suspicious control topics or public or external brokers, instead of flagging every retained message.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R229.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R229",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "mqtt.topic", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain real MQTT context and a retained-message indicator.",
                "The topic or broker context must be suspicious, such as control topics or public or external brokers.",
                "Ordinary retained state publishes on internal brokers should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic MQTT without retained indicators.",
                "Do not alert on internal retained status topics with no suspicious broker or control context."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+host+topic",
            falsePositives: new[] { "IoT platforms often use retained state topics intentionally on approved internal brokers." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive retained control topic sample", "negative retained internal state topic sample" });

        public R229_MqttRetainedTopicAbuseRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsMqtt(record) || !HasRetainIndicator(record))
                return NoMatch();

            var topic = NormalizeTopic(ExtractTopic(Text(record)));
            var host = BestHost(record);
            var suspiciousTopic = IsSuspiciousMqttControlTopic(topic);
            var riskyBroker = IsExternalAddress(record.Destination) || IsPublicMqttBroker(host);
            var automation = IsAutomationLikeProcess(record.ProcessName);
            if (!suspiciousTopic && !riskyBroker && !automation)
                return NoMatch();

            var matchedConditions = new List<string> { "mqtt_retained_indicator" };
            if (suspiciousTopic) matchedConditions.Add("suspicious_control_topic");
            if (riskyBroker) matchedConditions.Add("external_or_public_broker");
            if (automation) matchedConditions.Add("automation_process");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("mqtt.topic", string.IsNullOrWhiteSpace(topic) ? "(unknown)" : topic, "iot-ot"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "A retained MQTT publish targeted a suspicious topic or broker context.",
                "Severity is Medium because retained control or broad-scope topics can persist malicious state or commands across MQTT clients.",
                "Approved IoT platforms can legitimately use retained state topics on internal brokers.",
                "Validate the retained topic, broker approval status, and publishing client.",
                "Review whether the retained message could persist commands or configuration across device reconnects."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "Suspicious retained MQTT publish observed",
                "MQTT",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "mqtt-retained-indicator");
                    if (suspiciousTopic) confidence.AddEvidence(0.18, "suspicious-control-topic");
                    if (riskyBroker) confidence.AddEvidence(0.16, "external-or-public-broker");
                    if (automation) confidence.AddCorrelation(0.10, "automation-process");
                },
                cooldownKey: $"{record.Source}:{host}:{topic}");
        }
    }
}
