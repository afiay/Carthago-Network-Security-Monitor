// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R232_MdnsServiceEnumerationBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R232_MdnsServiceEnumerationBurstRule : IotOtAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R232",
            Name: "mDNS Service Enumeration Burst",
            Category: "IotOtAdvanced",
            Description: "Detects high-rate mDNS service enumeration only when the traffic carries real service-discovery semantics, not any stray bonjour or .local text.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R232.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtAdvancedProfile(
            ruleId: "R232",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "destination_or_host", "dns_qname" },
            evidenceFields: new[] { "count", "window_seconds", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must carry real mDNS service-enumeration semantics such as _services._dns-sd._udp.local.",
                "The same source should generate a high-rate burst within the configured window.",
                "Single or low-rate local service discovery should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic .local or bonjour mentions.",
                "Do not alert on isolated mDNS discovery."
            },
            minimumConfidence: 76,
            threshold: 20,
            window: TimeSpan.FromMinutes(2),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "query",
            falsePositives: new[] { "Approved device discovery or consumer-IoT onboarding tools can legitimately enumerate mDNS services." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive mdns enumeration burst sample", "negative single mdns query sample" });

        public R232_MdnsServiceEnumerationBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsMdnsContext(record) || !HasMdnsEnumerationSemantics(record))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 20, 5, 1000);
            var distinctValue = string.IsNullOrWhiteSpace(record.DnsQname) ? Text(record) : record.DnsQname!;
            var count = CountDistinctValues($"{Descriptor.RuleId}:{record.Source}", distinctValue, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "mdns_service_enumeration,distinct_query_burst", "rule")
            };
            evidence.AddRange(AnalystContext(
                "mDNS service enumeration semantics appeared across many distinct queries in a short window.",
                "Severity is Medium because broad mDNS enumeration is often a reconnaissance or onboarding step against local device ecosystems.",
                "Approved discovery tools, AV systems, or consumer-IoT onboarding can intentionally enumerate services.",
                "Validate whether the source belongs to sanctioned discovery or onboarding tooling.",
                "Review the enumerated service set to determine whether the scan targeted printers, media devices, or IoT hubs."));

            return MatchIot(
                context,
                SeverityLevel.Medium,
                "mDNS service-enumeration burst observed",
                "mDNS",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "mdns-service-enumeration");
                    confidence.AddEvidence(0.20, "distinct-query-burst");
                },
                count,
                window,
                $"{record.Source}:mdns-enumeration");
        }
    }
}
