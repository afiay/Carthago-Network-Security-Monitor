// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R187_DnsNullQueryUsageRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R187_DnsNullQueryUsageRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R187",
            Name: "DNS NULL Query Usage",
            Category: "DnsAdvanced",
            Description: "Detects structured DNS NULL queries, which are rare in normal environments and should not rely on generic text hints.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R187.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R187",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[] { "dns.qname", "dns.qtype", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured DNS NULL query.",
                "The qname should not be a benign validation or internal fallback name."
            },
            negativeConditions: new[]
            {
                "Do not alert on TXT queries or other qtypes.",
                "Do not alert on AnyText-only mentions of NULL."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Protocol research and DNS testing labs may deliberately use NULL queries." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive null query sample", "negative txt query sample" });

        public R187_DnsNullQueryUsageRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query)
                || !string.Equals(context.Record.DnsQtype, "NULL", StringComparison.OrdinalIgnoreCase)
                || LooksLikeBenignValidationQuery(query)
                || IsCommonSingleLabelFallbackName(query)
                || !_replay.Observe(context.Record, context.TimestampUtc))
            {
                return NoMatch();
            }

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "dns_null_query", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question used the NULL qtype, which is uncommon in ordinary enterprise traffic.",
                "Severity is Medium because NULL queries can indicate niche tooling, tunneling experiments, or unusual resolver interactions.",
                "Protocol research and lab environments may intentionally issue NULL queries.",
                "Review whether the source is a sanctioned DNS testing or research system.",
                "Check for adjacent TXT, ANY, or tunneling-like DNS behavior from the same source."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                "DNS NULL query observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "dns-null-query");
                },
                cooldownKey: $"{context.Record.Source}:{context.Record.Destination}:{NetworkBatch166170Evidence.Key(query)}");
        }
    }
}
