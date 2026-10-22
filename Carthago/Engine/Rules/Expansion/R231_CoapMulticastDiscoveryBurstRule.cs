// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R231_CoapMulticastDiscoveryBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R231_CoapMulticastDiscoveryBurstRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R231",
            Name: "CoAP Multicast Discovery Burst",
            Category: "IotOtAdvanced",
            Description: "Detects bursts of CoAP multicast or /.well-known/core discovery, while suppressing isolated or non-discovery CoAP traffic.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R231.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R231",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must contain concrete CoAP discovery semantics such as /.well-known/core or multicast discovery.",
                "The same source should generate a burst within the configured window.",
                "Isolated CoAP discovery should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on non-discovery CoAP telemetry.",
                "Do not alert on isolated multicast discovery."
            },
            minimumConfidence: 76,
            threshold: 10,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source",
            falsePositives: new[] { "Approved IoT onboarding or inventory workflows can intentionally enumerate CoAP resources." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive coap discovery burst sample", "negative single coap discovery sample" });

        public R231_CoapMulticastDiscoveryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var discovery = ContainsAnyValue(Text(record), "/.well-known/core", "coap discover", "resource discovery");
            var multicast = IsMulticastOrBroadcast(record.Destination);
            if (!IsCoapZigbeeContext(record) || (!discovery && !multicast))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 10, 3, 500);
            var count = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "coap_discovery_semantics", "burst_threshold" };
            if (multicast) matchedConditions.Add("multicast_or_broadcast_target");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                "CoAP discovery or multicast resource enumeration occurred in a high-rate burst.",
                "Severity is Medium because high-rate CoAP discovery is often an onboarding, inventory, or reconnaissance step against IoT devices.",
                "Approved IoT onboarding or inventory tools can intentionally enumerate CoAP endpoints.",
                "Validate whether the source belongs to sanctioned onboarding or discovery tooling.",
                "Review whether /.well-known/core enumeration targeted a broad device set unexpectedly."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "CoAP discovery burst observed",
                "CoAP",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "coap-discovery-semantics");
                    confidence.AddEvidence(0.20, "burst-threshold");
                    if (multicast) confidence.AddEvidence(0.08, "multicast-or-broadcast-target");
                },
                count,
                window,
                $"{record.Source}:coap-discovery");
        }
    }
}
