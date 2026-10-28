// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R183_DnssecRandomSubdomainSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R183_DnssecRandomSubdomainSpikeRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R183",
            Name: "DNSSEC Random Subdomain Spike",
            Category: "DnsAdvanced",
            Description: "Detects bursts of distinct DNSSEC-focused queries for random-looking subdomains instead of ordinary apex DNSSEC validation.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R183.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R183",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[] { "dns.qname", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a DNSSEC-related qtype such as DNSKEY, DS, or RRSIG.",
                "The queried name must include random-looking subdomains rather than only apex DNSSEC records.",
                "The same source must repeat distinct random subdomains within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on apex DNSKEY or DS lookups.",
                "Do not alert on benign validation prefixes or low-volume DNSSEC activity."
            },
            minimumConfidence: 74,
            threshold: 8,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "host",
            falsePositives: new[] { "Advanced DNS testing and DNSSEC validation labs may probe many signed names." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive dnssec random subdomain burst sample", "negative apex dnskey sample" });

        public R183_DnssecRandomSubdomainSpikeRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !IsDnssecQueryType(context.Record.DnsQtype))
                return NoMatch();

            var leftOfRoot = LeftOfRoot(query);
            if (string.IsNullOrWhiteSpace(leftOfRoot) || LooksLikeBenignValidationQuery(query))
                return NoMatch();

            var randomSubdomain = ShannonEntropy(leftOfRoot.Replace(".", string.Empty, StringComparison.Ordinal)) >= 3.0 || leftOfRoot.Length >= 16;
            if (!randomSubdomain)
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 100);
            var count = _window.Observe(context.Record, $"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.Destination}:{RootDomain(query)}", query, context.TimestampUtc, window, distinct: true);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "dnssec_qtype,random_subdomain,threshold_reached", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source repeatedly queried distinct random-looking subdomains with DNSSEC-related qtypes.",
                "Severity is Medium because this pattern is more consistent with aggressive namespace discovery or tunnel-like probing than routine DNSSEC validation.",
                "DNS research systems or signed-zone testing can generate similar bursts. Validate the source role before escalating.",
                "Review whether the source is also issuing ANY, CAA, or reverse-DNS enumeration traffic.",
                "Confirm whether the target root is expected to receive high-volume DNSSEC discovery traffic."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                "Random DNSSEC subdomain burst observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "dnssec-qtype");
                    confidence.AddEvidence(0.18, "random-subdomain");
                    confidence.AddEvidence(0.20, "threshold-reached");
                },
                count,
                window,
                $"{context.Record.Source}:{RootDomain(query)}");
        }
    }
}
