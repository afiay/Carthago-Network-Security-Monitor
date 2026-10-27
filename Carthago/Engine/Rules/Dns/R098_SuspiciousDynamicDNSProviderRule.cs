// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R098_SuspiciousDynamicDNSProviderRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R098_SuspiciousDynamicDNSProviderRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R098",
            Name: "Suspicious Dynamic DNS Provider",
            Category: "Dns",
            Description: "Flags DNS questions for dynamic-DNS provider domains when the queried label is first-seen or sufficiently random-looking, using the DNS qname as primary evidence.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R098.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R098",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[]
            {
                "source", "dns.qname", "dns.dynamicProvider", "dns.leftLabelEntropy",
                "baseline.reason", "count", "window_seconds", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "The qname must resolve beneath a known dynamic-DNS provider.",
                "The left-hand label must be materially random-looking, or the query must repeat in a short window with tunnel-favored characteristics."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not match on HTTP host text or generic destination names alone.",
                "Do not alert on a first-seen but human-readable dynamic-DNS label without repeat or TXT-like context."
            },
            minimumConfidence: 68,
            threshold: 2,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(60),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Home NAS, remote-access software, and legitimate lab tooling commonly use dynamic-DNS providers.",
                "Security engineers may intentionally use dynamic-DNS names during testing or remote administration."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "EntropyThreshold", "WindowSeconds", "RepeatThreshold", "MinimumLeftLabelLength" },
            requiredTests: new[]
            {
                "positive dynamic-dns sample",
                "negative missing DNS telemetry",
                "negative AnyText-only sample",
                "evidence and confidence assertion"
            });

        public R098_SuspiciousDynamicDNSProviderRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("Legitimate NAS, lab, or remote-access DDNS usage", "Tune by approved roots, owners, and device inventory instead of disabling the rule globally.")
        };

        protected override string? InvestigationHintOverride
            => "Identify the device or process that queried the dynamic-DNS name, confirm ownership, and review whether the DDNS root is part of an approved remote-access workflow.";

        protected override string? TuningHintOverride
            => "Allowlist approved dynamic-DNS roots or devices. Keep the rule DNS-driven so generic host strings cannot promote a high-severity alert.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch096100Evidence.Dns(context)
                || !TryGetDnsQuestion(context, out var query))
                return NoMatch();

            if (!IsDynamicDnsProvider(query))
                return NoMatch();

            var provider = RootDomain(query);
            var leftOfRoot = LeftOfRoot(query);
            if (string.IsNullOrWhiteSpace(leftOfRoot))
                return NoMatch();

            var baseline = ObserveBaseline("dns.dynamic-provider", context.Record.Source ?? "unknown", query, context, $"qtype={context.Record.DnsQtype}");

            var entropy = ShannonEntropy(leftOfRoot.Replace(".", string.Empty, StringComparison.Ordinal));
            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 2.80, 1.0, 8.0);
            var minimumLeftLabelLength = IntSetting(Descriptor.RuleId, "MinimumLeftLabelLength", 10, 4, 63);
            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 900, 60, 3600));
            var repeatThreshold = IntSetting(Descriptor.RuleId, "RepeatThreshold", 2, 2, 20);
            var repeatCount = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}:{provider}:{query}", context.Record.Id.ToString("N"), context.TimestampUtc, window);
            // Only a persisted baseline observation can establish first-seen status.
            // An in-process cache must not invent novelty when persistence fails.
            var firstSeen = baseline.IsFirstSeen;
            var randomLabel = entropy >= entropyThreshold;
            var longLeftLabel = leftOfRoot.Length >= minimumLeftLabelLength;
            var txtLikeLongLabel = IsTxtLikeDnsQueryType(context.Record.DnsQtype) && longLeftLabel;
            var repeatedSuspiciousQuery = repeatCount >= repeatThreshold
                && (randomLabel || longLeftLabel || IsTxtLikeDnsQueryType(context.Record.DnsQtype));

            if (!randomLabel && !txtLikeLongLabel && !repeatedSuspiciousQuery)
                return NoMatch();

            if (!firstSeen && !repeatedSuspiciousQuery && !randomLabel)
                return NoMatch();

            var highSeverity = repeatedSuspiciousQuery && (randomLabel || txtLikeLongLabel);
            var matchedConditions = new List<string> { "dynamic_dns_provider", "dns_qname_present" };
            if (firstSeen) matchedConditions.Add("first_seen_provider_domain");
            if (randomLabel) matchedConditions.Add("random_left_label");
            if (repeatedSuspiciousQuery) matchedConditions.Add("repeated_provider_query");
            if (txtLikeLongLabel) matchedConditions.Add("txt_like_long_left_label");

            var whyMatched = repeatedSuspiciousQuery
                ? $"The DNS question '{query}' targets a known dynamic-DNS provider and repeated {repeatCount} times within {window.TotalMinutes:F0} minutes with suspicious label characteristics."
                : $"The DNS question '{query}' targets a known dynamic-DNS provider and the left-hand label is unusually random-looking; baseline status: {baseline.Reason}.";
            var severityReason = highSeverity
                ? "Severity is High because the provider domain is both suspiciously shaped and repeated, which is more consistent with beaconing or operator-managed infrastructure than casual remote access."
                : "Severity is Medium because the provider is consumer-friendly and can be legitimate, but the DNS evidence still merits investigation when the label is random-looking or repeats unusually.";
            var falsePositives = "Remote-access tooling, NAS appliances, and lab environments often use dynamic-DNS providers legitimately. Validate device ownership and expected workflows before escalation.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.dynamicProvider", provider, "dns"),
                new("dns.leftLabelEntropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("baseline.observationCount", baseline.ObservationCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "baseline"),
                new("count", repeatCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Confirm the owner of the host or appliance that queried the dynamic-DNS name.",
                "Review follow-on TLS/HTTP traffic to the resolved destination and determine whether remote access or tunneling is expected.",
                "Allowlist only confirmed benign DDNS roots or devices."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Dynamic-DNS provider query observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "dynamic-dns-provider");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase) && firstSeen) confidence.AddBaseline(0.20, baseline.Reason);
                    else if (firstSeen) confidence.AddCorrelation(0.10, "first-seen-fallback");
                    if (randomLabel) confidence.AddEvidence(0.12, "random-left-label");
                    if (longLeftLabel) confidence.AddEvidence(0.08, "long-left-label");
                    if (repeatedSuspiciousQuery) confidence.AddEvidence(0.10, "repeated-provider-query");
                    if (txtLikeLongLabel) confidence.AddCorrelation(0.06, "txt-like-ddns-query");
                },
                count: repeatCount,
                window: window,
                cooldownKey: $"{context.Record.Source}:{provider}");
        }
    }
}
