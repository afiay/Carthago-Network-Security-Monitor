// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R192_PunycodeHomographDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R192_PunycodeHomographDomainRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R192",
            Name: "Punycode Homograph Domain",
            Category: "DnsAdvanced",
            Description: "Detects first-seen punycode labels under common ASCII TLDs that are more likely to support homograph abuse than legitimate IDN ccTLD usage.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R192.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R192",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "A non-TLD label must use punycode beneath a common ASCII TLD rather than an IDN ccTLD.",
                "The domain should be newly observed to reduce noise from known legitimate IDN destinations."
            },
            negativeConditions: new[]
            {
                "Do not alert on punycode TLDs that represent legitimate IDN ccTLD usage.",
                "Do not alert on previously established benign punycode domains without any novelty signal."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+query",
            falsePositives: new[] { "Legitimate internationalized brand domains can appear in punycode form." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive first-seen punycode homograph sample", "negative punycode tld sample" });

        public R192_PunycodeHomographDomainRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !TryGetPunycodeHomographLabel(query, out var label))
                return NoMatch();

            var baseline = ObserveBaseline("dns.punycode-homograph", context.Record.Source ?? "unknown", query, context, $"label={label}");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen(query, context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.punycodeLabel", label, "dns"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", "punycode_label,ascii_tld,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question used a newly observed punycode label beneath a common ASCII TLD, which is more consistent with potential homograph abuse than localized ccTLD IDN usage.",
                "Severity is Medium because homograph-style destinations are frequently used in phishing and impersonation campaigns.",
                "Some legitimate internationalized domains can still match. Validate brand ownership and browsing context before escalating.",
                "Check whether the destination visually impersonates a known service or identity provider.",
                "Review associated HTTP hostnames, certificates, and user interaction telemetry if available."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"Punycode homograph candidate observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.22, "punycode-label");
                    confidence.AddEvidence(0.12, "ascii-tld");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)) confidence.AddBaseline(0.16, baseline.Reason);
                    else confidence.AddCorrelation(0.10, "first-seen-fallback");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
