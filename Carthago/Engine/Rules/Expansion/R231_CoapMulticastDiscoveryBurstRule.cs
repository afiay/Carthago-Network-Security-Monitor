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
            distinctBy: "unique_packet",
            falsePositives: new[] { "Approved IoT onboarding or inventory workflows can intentionally enumerate CoAP resources." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive coap discovery burst sample", "negative single coap discovery sample" });

        public R231_CoapMulticastDiscoveryBurstRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch231235Evidence.Coap(r)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 10, 3, 500);
            var count = _observations.Observe(r.Source, r.Destination, r.Id, context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Parsed CoAP resource-discovery burst",
                "CoAP", new[] {
                    new DetectionEvidenceItem("count", count.ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "parsed_coap_get_well_known_core,unique_packet_burst", "rule") },
                confidence => { confidence.AddEvidence(0.24, "parsed-coap-discovery");
                    confidence.AddEvidence(0.20, "unique-packet-burst"); },
                count, window, r.Source + ":coap-discovery");
        }
    }
}
