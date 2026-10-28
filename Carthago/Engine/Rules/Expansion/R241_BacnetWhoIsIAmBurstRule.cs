// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R241_BacnetWhoIsIAmBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R241_BacnetWhoIsIAmBurstRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R241",
            Name: "BACnet Who-Is I-Am Burst",
            Category: "IotOtAdvanced",
            Description: "Detects BACnet Who-Is/I-Am discovery bursts using BACnet semantics and distinct-target/window evidence.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R241.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R241",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.OtIcsProtocol },
            requiredFields: new[] { "source", "destination_or_host", "bacnet_context", "who_is_or_i_am" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must contain BACnet context and Who-Is/I-Am discovery semantics.",
                "The same source should generate a burst or broad discovery pattern within the configured window.",
                "Single normal BACnet discovery exchanges should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on low-rate building automation discovery.",
                "Do not alert on non-BACnet UDP traffic using the same port."
            },
            minimumConfidence: 76,
            threshold: 15,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination",
            falsePositives: new[] { "Approved building-management discovery, commissioning, or inventory scans can legitimately trigger BACnet discovery bursts." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedBmsHosts" },
            requiredTests: new[] { "positive bacnet who-is burst sample", "negative single bacnet discovery sample" });

        public R241_BacnetWhoIsIAmBurstRule() : base(Rule, Profile) { }

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch241245Evidence.Bacnet(r, out var operation)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 15, 3, 1000);
            var count = _observations.Observe(r.Source, "bacnet-discovery", r.Id,
                context.TimestampUtc, window, false);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Parsed BACnet discovery burst observed",
                "BacnetDiscovery", new[] {
                    new DetectionEvidenceItem("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                    new DetectionEvidenceItem("window_seconds", ((int)window.TotalSeconds).ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "udp_bacnet,parsed_discovery_operation,packet_burst", "rule")
                }, confidence => { confidence.AddEvidence(0.28, "parsed-bacnet"); confidence.AddEvidence(0.24, "operation"); confidence.AddEvidence(0.18, "packet-burst"); }, count, window,
                r.Source + ":" + r.Destination + ":bacnet-discovery");
        }

    }
}
