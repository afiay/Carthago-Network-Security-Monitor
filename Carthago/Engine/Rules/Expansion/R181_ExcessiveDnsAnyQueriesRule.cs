// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R181_ExcessiveDnsAnyQueriesRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R181_ExcessiveDnsAnyQueriesRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R181",
            Name: "Excessive DNS ANY Queries",
            Category: "DnsAdvanced",
            Description: "Detects repeated structured DNS ANY queries from the same source instead of a single ANY query or generic text match.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R181.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R181",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[] { "dns.qname", "dns.qtype", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured DNS ANY query.",
                "The same source must repeat ANY queries within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on non-ANY queries.",
                "Do not alert on isolated single ANY lookups."
            },
            minimumConfidence: 72,
            threshold: 5,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+resolver",
            falsePositives: new[] { "Diagnostics and legacy DNS tooling can issue ANY queries during troubleshooting." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive repeated any query sample", "negative single any query sample" });

        public R181_ExcessiveDnsAnyQueriesRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !string.Equals(context.Record.DnsQtype, "ANY", StringComparison.OrdinalIgnoreCase))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 5, 2, 100);
            var key = $"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.Destination}";
            var count = CountWindowEvents(key, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "dns_any_query,threshold_reached", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source repeatedly issued structured DNS ANY queries in a short window.",
                "Severity is Medium because concentrated ANY queries often indicate reconnaissance, legacy tooling misuse, or unusual resolver behavior.",
                "Diagnostics and legacy resolvers can still generate ANY queries. Validate whether the source is an approved troubleshooting system.",
                "Review whether the source is enumerating many domains or using a legacy DNS toolkit.",
                "Confirm whether the resolver and source pairing are expected."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"Repeated DNS ANY queries observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "dns-any-query");
                    confidence.AddEvidence(0.22, "threshold-reached");
                },
                count,
                window,
                $"{context.Record.Source}:{context.Record.Destination}");
        }
    }
}
