// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R193_CloudBrandLookalikeDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R193_CloudBrandLookalikeDomainRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R193",
            Name: "Cloud Brand Lookalike Domain",
            Category: "DnsAdvanced",
            Description: "Detects newly observed DNS names with explicit brand-lookalike labels for common cloud and identity vendors instead of broad substring matching.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R193.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R193",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "One of the labels must exactly match a known cloud or identity lookalike token.",
                "The domain should be newly observed to reduce noise from long-established benign use."
            },
            negativeConditions: new[]
            {
                "Do not alert on legitimate vendor domains.",
                "Do not alert on previously established benign lookalike-like labels without novelty."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+query",
            falsePositives: new[] { "Some internal test domains can deliberately mimic brands for phishing training or red-team exercises." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive cloud brand lookalike sample", "negative legitimate vendor domain sample" });

        public R193_CloudBrandLookalikeDomainRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !TryGetCloudBrandLookalike(query, out var brand, out var matchedLabel))
                return NoMatch();

            var baseline = ObserveBaseline("dns.brand-lookalike", context.Record.Source ?? "unknown", query, context, $"brand={brand}");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen(query, context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.lookalikeBrand", brand, "dns"),
                new("dns.lookalikeLabel", matchedLabel, "dns"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", "brand_lookalike_label,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question contained a newly observed label that explicitly mimics a common cloud or identity brand.",
                "Severity is Medium because brand-lookalike domains are commonly used for phishing, credential theft, and fake login infrastructure.",
                "Phishing simulations and internal training environments may intentionally register lookalike domains.",
                "Validate ownership of the domain and whether it belongs to an approved training or red-team exercise.",
                "Review related web traffic, certificate names, and user interaction surrounding the query."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"Brand-lookalike DNS query observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "brand-lookalike-label");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)) confidence.AddBaseline(0.16, baseline.Reason);
                    else confidence.AddCorrelation(0.10, "first-seen-fallback");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
