// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R113_MQTTBrokerConnectionToUnapprovedHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R113_MQTTBrokerConnectionToUnapprovedHostRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R113",
            Name: "MQTT Broker Connection to Unapproved Host",
            Category: "IotOt",
            Description: "Detects MQTT connections to external or public broker infrastructure, while suppressing ordinary internal-broker traffic and keyword-only records.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R113.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R113",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "iot.protocolFamily", "iot.host", "network.destinationPort", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain concrete MQTT protocol context.",
                "The destination must be external or a known public MQTT broker host.",
                "Internal or .local broker traffic should remain suppressed at the detector level."
            },
            negativeConditions: new[]
            {
                "Do not alert from AnyText-only evidence.",
                "Do not alert on internal MQTT brokers without public or external characteristics.",
                "Do not alert on generic browser or web traffic that only mentions mqtt."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(30),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Sanctioned public MQTT brokers should be allowlisted via Approved.MqttBrokers.",
                "Cloud-connected IoT gateways may legitimately use hosted MQTT services."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive external mqtt broker sample",
                "negative internal mqtt broker sample",
                "negative anytext-only mqtt sample"
            });

        public R113_MQTTBrokerConnectionToUnapprovedHostRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Confirm whether the broker is externally hosted or public, identify the client process, and compare the broker against Approved.MqttBrokers before escalating.";

        protected override string? TuningHintOverride
            => "Use Approved.MqttBrokers to shadow sanctioned brokers. Keep the detector focused on external or public MQTT endpoints rather than all broker traffic.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch111115Evidence.Mqtt(context) || !IsInternalAddress(record.Source))
                return NoMatch();

            var host = BestHost(record);
            var externalDestination = IsExternalAddress(record.Destination);
            var publicBroker = IsPublicMqttBroker(host);
            if (!externalDestination && !publicBroker)
                return NoMatch();


            var matchedConditions = new List<string> { "mqtt_protocol_context", "external_or_public_broker" };
            if (externalDestination) matchedConditions.Add("external_destination");
            if (publicBroker) matchedConditions.Add("public_broker_host");

            var whyMatched = $"{record.Source} connected to MQTT broker target {(string.IsNullOrWhiteSpace(host) ? record.Destination : host)} with destination port {record.DestinationPort}.";
            var severityReason = "Severity is High because the MQTT traffic targets an external or public broker instead of an internal broker path.";
            var falsePositives = "Approved public brokers and cloud-connected gateways may be expected. Validate the destination against environment allowlists before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Validate whether the broker is a sanctioned MQTT endpoint for this environment.",
                "Review the client process and whether the host is an expected IoT gateway or application broker.",
                "Add sanctioned brokers to Approved.MqttBrokers instead of weakening the rule broadly."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "MQTT broker connection to external or public host",
                "MQTT",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "mqtt-protocol-context");
                    confidence.AddEvidence(0.24, "external-or-public-broker");
                    if (externalDestination) confidence.AddCorrelation(0.10, "external-destination");
                    if (publicBroker) confidence.AddCorrelation(0.08, "public-broker-host");
                },
                cooldownKey: $"{record.Source}:{host}:{record.Destination}");
        }

    }
}
