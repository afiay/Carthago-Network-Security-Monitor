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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsBacnetContext(record) || !HasBacnetWhoIsIAmSemantics(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 15, 3, 1000);
            var value = string.Join("|", record.Destination ?? string.Empty, BestHost(record), Text(record));
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}", value, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "bacnet_context,whois_iam_semantics,distinct_discovery_burst", "rule")
            };
            evidence.AddRange(AnalystContext(
                "BACnet Who-Is/I-Am discovery semantics appeared in a bursty or broad pattern.",
                "Severity is Medium because BACnet discovery can reveal building automation devices, object inventory, and control-system topology.",
                "Approved BMS commissioning and inventory workflows can intentionally generate BACnet discovery bursts.",
                "Validate whether the source is an approved BMS, engineering workstation, or commissioning tool.",
                "Review whether follow-on BACnet reads/writes or cross-segment building automation traffic occurred."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "BACnet Who-Is/I-Am discovery burst observed",
                "BacnetDiscovery",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "bacnet-context");
                    confidence.AddEvidence(0.24, "whois-iam-semantics");
                    confidence.AddEvidence(0.18, "distinct-discovery-burst");
                },
                count,
                window,
                $"{record.Source}:bacnet-discovery");
        }
    }
}
