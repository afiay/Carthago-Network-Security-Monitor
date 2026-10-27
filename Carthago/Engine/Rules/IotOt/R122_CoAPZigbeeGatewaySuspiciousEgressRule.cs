// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R122_CoAPZigbeeGatewaySuspiciousEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R122_CoAPZigbeeGatewaySuspiciousEgressRule : IotOtPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch116120Window _observations = new();
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R122",
            Name: "CoAP / Zigbee Gateway Suspicious Egress",
            Category: "IotOt",
            Description: "Detects suspicious external egress from CoAP or Zigbee gateway-like traffic, while suppressing isolated weak matches that lack gateway context or repetition.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R122.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R122",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain CoAP or Zigbee gateway context.",
                "The destination must be external.",
                "Gateway-specific context or repeated egress should be present."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal CoAP or Zigbee traffic.",
                "Do not alert on isolated weak CoAP matches without gateway indicators."
            },
            minimumConfidence: 78,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved cloud-connected IoT gateways may legitimately forward telemetry externally."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive zigbee gateway egress sample",
                "negative internal coap sample"
            });

        public R122_CoAPZigbeeGatewaySuspiciousEgressRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsInternalAddress(record.Source) || !IsExternalAddress(record.Destination)
                || !NetworkBatch121125Evidence.CoapOrGateway(context, out var directCoap, out var gatewayContext))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 500);
            // Only validated observations enter the bounded, instance-owned
            // window; replays of the same packet identity cannot raise count.
            var count = _observations.Count($"{record.Source}:{record.Destination}",
                record.Id, context.TimestampUtc, window);
            if (!gatewayContext && !directCoap && count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "coap_or_zigbee_context", "external_destination" };
            if (gatewayContext) matchedConditions.Add("gateway_context");
            if (directCoap) matchedConditions.Add("coap_port_context");
            if (count >= threshold) matchedConditions.Add("repeated_egress_threshold");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "CoAP or Zigbee gateway-like traffic reached an external destination with gateway or repeated-egress characteristics.",
                "Severity is High because gateway protocols such as CoAP or Zigbee should not egress externally without explicit approval.",
                "Approved cloud-connected gateways may legitimately forward telemetry externally.",
                "Validate whether the source is an approved cloud-connected gateway or bridge.",
                "Review the destination, cadence, and payload context for data exfiltration or command relay."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "CoAP or Zigbee gateway suspicious external egress",
                "CoAP/Zigbee",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "coap-or-zigbee-context");
                    confidence.AddEvidence(0.20, "external-destination");
                    if (gatewayContext) confidence.AddEvidence(0.12, "gateway-context");
                    if (count >= threshold) confidence.AddEvidence(0.08, "repeated-egress-threshold");
                },
                count: count,
                window: window,
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
