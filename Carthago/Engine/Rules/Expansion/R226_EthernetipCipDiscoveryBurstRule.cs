// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R226_EthernetipCipDiscoveryBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R226_EthernetipCipDiscoveryBurstRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R226",
            Name: "EtherNetIP CIP Discovery Burst",
            Category: "IotOtAdvanced",
            Description: "Detects bursts of EtherNet/IP CIP discovery such as ListIdentity across multiple destinations, instead of any stray CIP keyword.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R226.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R226",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must contain concrete CIP discovery semantics such as ListIdentity.",
                "The same source should probe many distinct destinations in a short window.",
                "Routine single CIP sessions should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic CIP traffic without discovery semantics.",
                "Do not alert on isolated or low-count discovery traffic."
            },
            minimumConfidence: 76,
            threshold: 8,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "destination",
            falsePositives: new[] { "Approved asset inventory or OT discovery tooling can intentionally enumerate CIP devices." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive cip discovery burst sample", "negative single cip session sample" });

        public R226_EthernetipCipDiscoveryBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsCipContext(record) || !HasCipDiscoverySemantics(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 500);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}", record.Destination ?? BestHost(record), context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "cip_discovery_semantics,destination_burst_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "CIP discovery semantics such as ListIdentity were sent to many distinct destinations in a short window.",
                "Severity is Medium because high-rate CIP discovery often reflects asset reconnaissance or unaudited scanning in OT networks.",
                "Approved inventory or OT discovery tools can intentionally enumerate PLCs and adapters.",
                "Validate whether the source belongs to sanctioned discovery or engineering tooling.",
                "Review the destination spread and timing for reconnaissance against PLCs or adapters."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "EtherNet/IP discovery burst observed",
                "EtherNetIP/CIP",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "cip-discovery-semantics");
                    confidence.AddEvidence(0.20, "destination-burst-threshold");
                },
                count,
                window,
                $"{record.Source}:cip-discovery");
        }
    }
}
