// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R239_Zigbee2MqttBridgeInternetAccessRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R239_Zigbee2MqttBridgeInternetAccessRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R239",
            Name: "Zigbee2MQTT Bridge Internet Access",
            Category: "IotOtAdvanced",
            Description: "Detects Zigbee2MQTT bridge context communicating with external destinations, especially MQTT control or bridge topics.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R239.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R239",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Mqtt },
            requiredFields: new[] { "source", "destination_or_host", "zigbee2mqtt_context" },
            evidenceFields: new[] { "host", "mqtt.topic", "matched_conditions" },
            positiveConditions: new[]
            {
                "The source/process/payload must identify Zigbee2MQTT or z2m bridge context.",
                "The destination must be external.",
                "MQTT bridge/control topic context increases confidence, but internet access from the bridge alone is suspicious."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal Zigbee2MQTT to local broker traffic.",
                "Do not alert on generic MQTT clients without Zigbee2MQTT context."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host",
            falsePositives: new[] { "Some deployments intentionally use a cloud MQTT broker; this should be explicitly approved because it changes the home/IoT trust boundary." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedMqttBrokers" },
            requiredTests: new[] { "positive z2m external mqtt sample", "negative z2m local broker sample" });

        public R239_Zigbee2MqttBridgeInternetAccessRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var topic = NormalizeTopic(ExtractTopic(Text(record)));
            var mqttContext = ContainsAnyValue(record.ApplicationProtocol, "mqtt") || ContainsAnyValue(record.ApplicationService, "mqtt") || ContainsAnyValue(Text(record), "mqtt", "zigbee2mqtt", "z2m");
            var suspiciousTopic = IsSuspiciousMqttControlTopic(topic) || ContainsAnyValue(topic, "zigbee2mqtt/bridge", "zigbee2mqtt/+/set", "/set", "/availability");
            if (!IsZigbee2MqttBridge(record) || !mqttContext || !IsInternalToExternal(record))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("host", host, "flow"),
                new("mqtt.topic", string.IsNullOrWhiteSpace(topic) ? "unknown" : topic, "mqtt"),
                new("matched_conditions", suspiciousTopic ? "zigbee2mqtt_context,external_destination,mqtt_context,bridge_or_control_topic" : "zigbee2mqtt_context,external_destination,mqtt_context", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A Zigbee2MQTT bridge communicated with an external MQTT/cloud destination.",
                "Severity is High because exposing bridge traffic externally can leak smart-home state or allow control-topic abuse if broker credentials are compromised.",
                "Cloud MQTT broker deployments may be legitimate but should be explicitly documented and monitored.",
                "Confirm whether the MQTT broker is local, approved cloud-hosted, or unknown.",
                "Review topics for command/control namespaces, retained messages, and bridge administrative operations."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "Zigbee2MQTT bridge accessed external MQTT/cloud destination",
                "Zigbee2MqttExternal",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "zigbee2mqtt-context");
                    confidence.AddEvidence(0.28, "external-destination");
                    confidence.AddEvidence(0.12, "mqtt-context");
                    if (suspiciousTopic) confidence.AddCorrelation(0.08, "bridge-or-control-topic");
                },
                cooldownKey: $"{record.Source}:{host}:zigbee2mqtt-external");
        }
    }
}
