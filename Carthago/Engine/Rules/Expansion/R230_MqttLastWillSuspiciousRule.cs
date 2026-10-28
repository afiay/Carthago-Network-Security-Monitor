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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch226230Evidence.LastWill(r)) return NoMatch();
            var suspicious = r.MqttWillControlTopicObserved;
            var external = NetworkBatch226230Evidence.Public(r.Destination);
            if (!suspicious && !external
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "MQTT CONNECT will with risk context",
                "MQTT", new[] {
                    new DetectionEvidenceItem("mqtt.topic", "[REDACTED]", "iot-ot"),
                    new DetectionEvidenceItem("matched_conditions",
                        suspicious ? "parsed_connect_will,control_topic" : "parsed_connect_will,external_broker", "rule") },
                confidence => { confidence.AddEvidence(0.22, "parsed-connect-will");
                    if (suspicious) confidence.AddEvidence(0.18, "control-topic");
                    if (external) confidence.AddEvidence(0.16, "external-broker"); },
                cooldownKey: r.Source + ":" + r.Destination + ":mqtt-will");
        }
    }
}
