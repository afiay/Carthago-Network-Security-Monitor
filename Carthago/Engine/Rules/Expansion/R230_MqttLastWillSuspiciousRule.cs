// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R230_MqttLastWillSuspiciousRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R230_MqttLastWillSuspiciousRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R230",
            Name: "MQTT Last Will Suspicious",
            Category: "IotOtAdvanced",
            Description: "Detects suspicious MQTT last-will usage only when it targets risky topics or public or external brokers, instead of any ordinary LWT configuration.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R230.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R230",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "mqtt.topic", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain real MQTT last-will indicators.",
                "The topic or broker context must be suspicious, such as control topics or public or external brokers.",
                "Routine availability LWTs on internal brokers should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic MQTT without last-will semantics.",
                "Do not alert on benign internal availability LWT topics."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+host+topic",
            falsePositives: new[] { "Approved MQTT clients frequently use LWT on internal brokers for availability state." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive last will control topic sample", "negative internal availability lwt sample" });

        public R230_MqttLastWillSuspiciousRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsMqtt(record) || !HasWillIndicator(record))
                return NoMatch();

            var topic = NormalizeTopic(ExtractTopic(Text(record)));
            var host = BestHost(record);
            var suspiciousTopic = IsSuspiciousMqttControlTopic(topic);
            var riskyBroker = IsExternalAddress(record.Destination) || IsPublicMqttBroker(host);
            var automation = IsAutomationLikeProcess(record.ProcessName);
            if (!suspiciousTopic && !riskyBroker && !automation)
                return NoMatch();

            var matchedConditions = new List<string> { "mqtt_last_will_indicator" };
            if (suspiciousTopic) matchedConditions.Add("suspicious_control_topic");
            if (riskyBroker) matchedConditions.Add("external_or_public_broker");
            if (automation) matchedConditions.Add("automation_process");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("mqtt.topic", string.IsNullOrWhiteSpace(topic) ? "(unknown)" : topic, "iot-ot"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "MQTT last-will configuration targeted a suspicious topic or broker context.",
                "Severity is Medium because last-will messages can be abused to persist alerts, commands, or fallback behavior when clients disconnect.",
                "Routine device availability LWTs on approved internal brokers are common and should stay suppressed.",
                "Validate the LWT topic, broker approval status, and client intent.",
                "Review whether the will message could trigger control workflows or automated responses on disconnect."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "Suspicious MQTT last-will usage observed",
                "MQTT",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "mqtt-last-will-indicator");
                    if (suspiciousTopic) confidence.AddEvidence(0.18, "suspicious-control-topic");
                    if (riskyBroker) confidence.AddEvidence(0.16, "external-or-public-broker");
                    if (automation) confidence.AddCorrelation(0.10, "automation-process");
                },
                cooldownKey: $"{record.Source}:{host}:{topic}");
        }
    }
}
