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

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch231235Evidence.Mdns(r, out var query)) return NoMatch();
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 120, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 20, 5, 1000);
            var count = _observations.Observe(r.Source, query, r.Id, context.TimestampUtc, window, true);
            if (count < threshold) return NoMatch();
            return MatchIot(context, SeverityLevel.Medium, "Parsed mDNS PTR service enumeration burst",
                "mDNS", new[] {
                    new DetectionEvidenceItem("count", count.ToString(), "rule"),
                    new DetectionEvidenceItem("matched_conditions", "parsed_mdns_ptr,distinct_service_queries", "rule") },
                confidence => { confidence.AddEvidence(0.24, "parsed-mdns-ptr");
                    confidence.AddEvidence(0.20, "distinct-service-queries"); },
                count, window, r.Source + ":mdns-enumeration");
        }
    }
}
