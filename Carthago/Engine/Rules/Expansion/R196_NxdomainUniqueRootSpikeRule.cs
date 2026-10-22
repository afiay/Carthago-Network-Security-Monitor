// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R196_NxdomainUniqueRootSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R196_NxdomainUniqueRootSpikeRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R196",
            Name: "NXDOMAIN Unique Root Spike",
            Category: "DnsAdvanced",
            Description: "Detects sources that trigger many distinct NXDOMAIN roots in a short window instead of isolated typos or single-root misses.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R196.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R196",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_rcode" },
            evidenceFields: new[] { "dns.qname", "dns.rcode", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured NXDOMAIN DNS result.",
                "The same source must trigger NXDOMAIN for many distinct root domains within the configured window.",
                "Common fallback names and validation prefixes should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated typos or repeated misses for a single root.",
                "Do not alert on common fallback names such as wpad."
            },
            minimumConfidence: 74,
            threshold: 10,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "root_domain",
            falsePositives: new[] { "Web crawlers, misconfigured software, and some security tools can produce high NXDOMAIN volumes." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive unique nxdomain spike sample", "negative repeated single-root nxdomain sample" });

        public R196_NxdomainUniqueRootSpikeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !IsNxDomain(context.Record) || LooksLikeBenignValidationQuery(query) || IsCommonSingleLabelFallbackName(query))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 10, 3, 200);
            var root = RootDomain(query);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}", root, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "nxdomain,distinct_root_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source triggered NXDOMAIN responses for many distinct roots in a short period.",
                "Severity is Medium because this pattern often reflects DGA churn, aggressive reconnaissance, or broken software generating disposable domains.",
                "Web crawlers, malware sandboxes, and misconfigured software can produce similar spikes. Validate the source role before escalating.",
                "Review whether the same source also exhibits DGA, high-risk TLD, or short-TTL DNS patterns.",
                "Inspect process context and any follow-on successful queries after the NXDOMAIN burst."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"NXDOMAIN unique-root spike observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "nxdomain");
                    confidence.AddEvidence(0.22, "distinct-root-threshold");
                },
                count,
                window,
                context.Record.Source);
        }
    }
}
