// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R188_ActiveDirectorySrvEnumerationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R188_ActiveDirectorySrvEnumerationRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R188",
            Name: "Active Directory SRV Enumeration",
            Category: "DnsAdvanced",
            Description: "Detects short-window bursts of distinct AD SRV queries rather than single routine AD service discovery lookups.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R188.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R188",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Identity },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The query must be a structured Active Directory SRV lookup.",
                "The same source must issue multiple distinct AD SRV queries in a short window."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated single AD service discovery lookups.",
                "Do not alert on non-SRV or unrelated DNS names."
            },
            minimumConfidence: 72,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "host",
            falsePositives: new[] { "Domain join workflows and legitimate AD-aware clients can issue some SRV lookups normally." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive ad srv burst sample", "negative single ad srv lookup sample" });

        public R188_ActiveDirectorySrvEnumerationRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !IsAdSrvQuery(query))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 50);
            var root = RootDomain(query);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}:{root}", query, context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "ad_srv_query,distinct_srv_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source issued multiple distinct Active Directory SRV lookups in a short period.",
                "Severity is Medium because bursts of AD SRV discovery often indicate environment mapping or domain-services reconnaissance.",
                "Domain join, GPO refresh, and legitimate management workflows can issue some SRV queries. The burst threshold helps suppress routine traffic.",
                "Review whether the source is a newly joined client or an approved administrative system.",
                "Check for adjacent LDAP, Kerberos, or reverse-DNS discovery from the same source."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"AD SRV enumeration observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "ad-srv-query");
                    confidence.AddEvidence(0.20, "distinct-srv-threshold");
                },
                count,
                window,
                $"{context.Record.Source}:{root}");
        }
    }
}
