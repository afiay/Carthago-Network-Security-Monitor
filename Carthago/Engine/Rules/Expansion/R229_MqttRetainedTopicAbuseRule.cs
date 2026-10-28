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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch226230Evidence.RetainedPublish(r)) return NoMatch();
            var suspicious = NetworkBatch226230Evidence.SuspiciousTopic(r.MqttTopic);
            var external = NetworkBatch226230Evidence.Public(r.Destination);
            if (!suspicious && !external
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Retained MQTT PUBLISH with risk context",
                "MQTT", new[] {
                    new DetectionEvidenceItem("mqtt.topic", "[REDACTED]", "iot-ot"),
                    new DetectionEvidenceItem("matched_conditions",
                        suspicious ? "parsed_retained_publish,control_topic" : "parsed_retained_publish,external_broker", "rule") },
                confidence => { confidence.AddEvidence(0.22, "parsed-retained-publish");
                    if (suspicious) confidence.AddEvidence(0.18, "control-topic");
                    if (external) confidence.AddEvidence(0.16, "external-broker"); },
                cooldownKey: r.Source + ":" + r.Destination + ":mqtt-retain");
        }
    }
}
