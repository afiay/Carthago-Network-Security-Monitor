// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R097_ExcessiveUniqueSubdomainsRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R097_ExcessiveUniqueSubdomainsRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R097",
            Name: "Excessive Unique Subdomains",
            Category: "Dns",
            Description: "Detects many distinct subdomains for the same root from one source within a time window, using DNS qname structure rather than text-only indicators.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R097.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R097",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[]
            {
                "source", "dns.qname", "dns.rootDomain", "dns.uniqueSubdomains",
                "dns.latestLabelEntropy", "matched_conditions", "count", "window_seconds"
            },
            positiveConditions: new[]
            {
                "A DNS qname with a root domain and left-hand label must be present.",
                "Distinct subdomains for the same root must exceed a threshold within a configured window.",
                "The latest subdomain should look enumeration- or tunneling-like rather than a single benign label."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not infer subdomain bursts from AnyText or port 53 alone.",
                "Suppress known validation, SaaS, and platform telemetry roots."
            },
            minimumConfidence: 74,
            threshold: 25,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+root_domain",
            falsePositives: new[]
            {
                "Security tooling, CDNs, and some SaaS products can legitimately generate many subdomains.",
                "Certificate validation and service-discovery workflows may create left-hand-label churn."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "EntropyThreshold" },
            requiredTests: new[]
            {
                "positive burst of unique subdomains",
                "negative missing DNS telemetry",
                "negative AnyText-only sample",
                "threshold and window assertion"
            });

        public R097_ExcessiveUniqueSubdomainsRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("CDN, anti-malware, or cloud telemetry domains with many left-hand labels", "Use approved roots or higher thresholds before promoting the rule in production.")
        };

        protected override string? InvestigationHintOverride
            => "Review the number of distinct subdomains per root, the source process or device, and whether the labels resemble tunneling, brute-force enumeration, or service discovery.";

        protected override string? TuningHintOverride
            => "Tune with approved roots and threshold/window settings. Do not reduce the rule to host text or port-only evidence.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch096100Evidence.Dns(context)
                || !TryGetDnsQuestion(context, out var query))
                return NoMatch();

            var root = RootDomain(query);
            if (LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(root))
                return NoMatch();

            var leftOfRoot = LeftOfRoot(query);
            if (string.IsNullOrWhiteSpace(leftOfRoot))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 30, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 25, 5, 500);
            var uniqueCount = CountDistinctValues($"{Descriptor.RuleId}:{context.Record.Source}:{root}", leftOfRoot, context.TimestampUtc, window);
            if (uniqueCount < threshold)
                return NoMatch();

            var latestLabelEntropy = ShannonEntropy(leftOfRoot.Replace(".", string.Empty, StringComparison.Ordinal));
            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.10, 1.0, 8.0);
            if (latestLabelEntropy < entropyThreshold && leftOfRoot.Length < 12)
                return NoMatch();

            var highSeverity = uniqueCount >= threshold + 10 || latestLabelEntropy >= entropyThreshold + 0.35;
            var matchedConditions = new List<string> { "unique_subdomain_threshold", "dns_qname_present", "latest_label_complexity" };
            if (highSeverity)
                matchedConditions.Add("strong_burst_signal");

            var whyMatched = $"{context.Record.Source} queried {uniqueCount} distinct subdomains beneath {root} within {window.TotalMinutes:F0} minutes.";
            var severityReason = highSeverity
                ? "Severity is High because the distinct-count threshold and label complexity indicate likely tunneling or enumeration, not a single noisy DNS query."
                : "Severity is Medium because the root exceeded the subdomain threshold, but the latest label complexity is only moderately suspicious.";
            var falsePositives = "CDN sharding, software telemetry, and service discovery can generate many subdomains. Validate the root owner and label patterns before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.uniqueSubdomains", uniqueCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.latestLabelEntropy", latestLabelEntropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("threshold", threshold.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect other queries to the same root and determine whether the source is staging data into subdomain labels.",
                "Review adjacent HTTP/TLS connections for the same root or newly resolved IPs.",
                "Allowlist only confirmed benign roots or raise the threshold for expected high-cardinality DNS patterns."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Distinct subdomain burst observed for {root}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "distinct-subdomain-threshold");
                    confidence.AddEvidence(0.12, "windowed-behavior");
                    confidence.AddEvidence(0.14, "latest-label-complexity");
                    if (highSeverity) confidence.AddEvidence(0.12, "strong-burst");
                    if (!IsKnownTelemetryRoot(root)) confidence.AddCorrelation(0.08, "non-approved-root");
                },
                count: uniqueCount,
                window: window,
                cooldownKey: $"{context.Record.Source}:{root}");
        }
    }
}
