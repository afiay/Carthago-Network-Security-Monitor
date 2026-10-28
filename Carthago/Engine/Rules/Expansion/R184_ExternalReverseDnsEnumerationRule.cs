// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R184_ExternalReverseDnsEnumerationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R184_ExternalReverseDnsEnumerationRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R184",
            Name: "External Reverse DNS Enumeration",
            Category: "DnsAdvanced",
            Description: "Detects repeated reverse-DNS lookups sent to external resolvers instead of isolated PTR traffic.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R184.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R184",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The query must be a structured reverse-DNS name.",
                "The destination must be an external resolver or public-facing endpoint.",
                "The same source must enumerate many distinct reverse-DNS names within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated PTR lookups.",
                "Do not alert on reverse-DNS queries that stay on trusted internal resolver paths."
            },
            minimumConfidence: 74,
            threshold: 10,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "host",
            falsePositives: new[] { "Troubleshooting tools and security assessments can legitimately perform bulk PTR lookups." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive external ptr enumeration sample", "negative isolated ptr sample" });

        public R184_ExternalReverseDnsEnumerationRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !IsReverseLookupQuery(query) || !IsExternalEndpoint(context.Record.Destination) || !string.Equals(context.Record.DnsQtype, "PTR", StringComparison.OrdinalIgnoreCase))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 10, 3, 200);
            var count = _window.Observe(context.Record, $"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.Destination}", query, context.TimestampUtc, window, distinct: true);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "reverse_dns_query,external_resolver,threshold_reached", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source performed many distinct reverse-DNS lookups against an external resolver.",
                "Severity is Medium because concentrated PTR lookups often indicate infrastructure mapping or reconnaissance.",
                "Asset inventory tools and approved scanning jobs can generate similar reverse-DNS bursts.",
                "Confirm whether the source is an approved inventory or scanning system.",
                "Review whether the same source also performs zone transfer, ANY, or NXDOMAIN spike behavior."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                "External reverse-DNS enumeration observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "reverse-dns-query");
                    confidence.AddEvidence(0.18, "external-resolver");
                    confidence.AddEvidence(0.18, "threshold-reached");
                },
                count,
                window,
                $"{context.Record.Source}:{context.Record.Destination}");
        }
    }
}
