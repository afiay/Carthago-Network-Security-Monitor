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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch236240Evidence.BridgeMqtt(r, out var control)
                || _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc,
                    TimeSpan.FromMinutes(10), false) == 0) return NoMatch();
            return MatchIot(context, SeverityLevel.High,
                "Attributed Zigbee2MQTT bridge requested external MQTT broker", "Zigbee2MqttExternal",
                new[] {
                    new DetectionEvidenceItem("matched_conditions", control
                        ? "bridge_process,parsed_mqtt,external_broker,control_topic_class"
                        : "bridge_process,parsed_mqtt,external_broker", "rule"),
                    new DetectionEvidenceItem("mqtt.topic", "[REDACTED]", "mqtt") },
                c => { c.AddEvidence(0.38, "attributed-bridge-process");
                    c.AddEvidence(0.30, "parsed-mqtt-operation");
                    c.AddCorrelation(0.18, "external-broker"); },
                cooldownKey: r.Source + ":" + r.Destination + ":zigbee2mqtt");
        }
    }
}
