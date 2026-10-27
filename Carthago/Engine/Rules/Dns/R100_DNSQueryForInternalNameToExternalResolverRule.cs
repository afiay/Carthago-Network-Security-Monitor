// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R100_DNSQueryForInternalNameToExternalResolverRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R100_DNSQueryForInternalNameToExternalResolverRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R100",
            Name: "DNS Query for Internal Name to External Resolver",
            Category: "Dns",
            Description: "Detects repeated DNS questions for internal-only names sent to a public resolver, using actual DNS qname and resolver telemetry rather than generic host text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R100.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R100",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "destination_or_host" },
            evidenceFields: new[]
            {
                "dns.qname", "dns.internalSuffix", "dns.commonFallbackName", "resolver.destination", "count", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "The qname must be single-label or end with an internal-only suffix.",
                "The resolver destination must be external and the behavior should repeat within a short window."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not infer resolver abuse from port 53 alone.",
                "Do not page on a one-off typo or local-only resolver query."
            },
            minimumConfidence: 70,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+resolver",
            falsePositives: new[]
            {
                "Resolver misconfiguration, captive portals, or split-DNS mistakes can leak internal names without malicious intent.",
                "New devices can generate single-label fallback queries during onboarding."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive repeated internal-name leak sample",
                "negative missing DNS telemetry",
                "negative port-only sample",
                "threshold and evidence assertion"
            });

        public R100_DNSQueryForInternalNameToExternalResolverRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("Split-DNS or resolver fallback misconfiguration", "Tune by approved resolvers and monitor repeated leakage patterns before suppressing the rule.")
        };

        protected override string? InvestigationHintOverride
            => "Determine whether the source is using an approved resolver, inspect leaked internal names, and confirm whether split-DNS or VPN resolver configuration is broken.";

        protected override string? TuningHintOverride
            => "Tune by approved resolvers and threshold/window values. Keep the rule dependent on actual DNS qname telemetry and repeated behavior.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch096100Evidence.Dns(context, singleLabel: true)
                || !TryGetDnsQuestion(context, out var query))
                return NoMatch();

            // Internal namespace leakage requires a private client and a
            // globally routable resolver address, not an arbitrary host string.
            if (!NetworkBatch096100Evidence.PrivateClient(context.Record.Source)
                || !NetworkBatch096100Evidence.PublicResolver(context.Record.Destination))
                return NoMatch();

            var suffix = query.Contains('.')
                ? query[(query.LastIndexOf('.') + 1)..]
                : "single-label";
            var internalName = LooksLikeInternalOnlyDnsName(query);
            if (!internalName)
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 100);
            var count = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.Destination}:{query}", context.Record.Id.ToString("N"), context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var commonFallbackName = IsCommonSingleLabelFallbackName(query);
            if (commonFallbackName && count < threshold + 2)
                return NoMatch();

            var highSeverity = !commonFallbackName
                && (count >= threshold + 2 || query.EndsWith(".internal", StringComparison.OrdinalIgnoreCase) || query.EndsWith(".corp", StringComparison.OrdinalIgnoreCase));
            var matchedConditions = new List<string> { "internal_name_pattern", "external_resolver_destination", "repeated_behavior_threshold" };
            if (highSeverity)
                matchedConditions.Add("high_value_internal_namespace");
            if (commonFallbackName)
                matchedConditions.Add("common_single_label_fallback_escalated");

            var whyMatched = $"{context.Record.Source} sent the internal-only name '{query}' to external resolver {context.Record.Destination} {count} times within {window.TotalMinutes:F0} minutes.";
            var severityReason = highSeverity
                ? "Severity is High because internal namespace leakage is repeated and targets a public resolver, increasing the chance of data exposure or external discovery."
                : "Severity is Medium because the behavior repeats, but the evidence may still reflect a resolver misconfiguration rather than malicious activity.";
            var falsePositives = "Split-DNS mistakes, VPN resolver failures, and onboarding issues can cause repeated internal-name leakage. Confirm resolver configuration before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.internalSuffix", suffix, "dns"),
                new("dns.commonFallbackName", commonFallbackName ? "true" : "false", "dns"),
                new("resolver.destination", context.Record.Destination ?? "unknown", "dns"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Verify whether the host is configured to use an approved internal resolver or whether VPN/split-DNS settings are broken.",
                "Review the leaked names for sensitive systems, internal zones, or discovery activity.",
                "Tune by approved resolvers or known onboarding workflows rather than allowing generic resolver traffic."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Internal DNS name sent to external resolver: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "internal-name-pattern");
                    confidence.AddEvidence(0.22, "external-resolver");
                    confidence.AddEvidence(0.16, "repeated-threshold");
                    if (highSeverity) confidence.AddCorrelation(0.10, "sensitive-internal-namespace");
                },
                count: count,
                window: window,
                cooldownKey: $"{context.Record.Source}:{context.Record.Destination}:{query}");
        }
    }
}
