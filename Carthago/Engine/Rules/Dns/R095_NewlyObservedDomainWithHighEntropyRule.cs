// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R095_NewlyObservedDomainWithHighEntropyRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R095_NewlyObservedDomainWithHighEntropyRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R095",
            Name: "Newly Observed Domain With High Entropy",
            Category: "Dns",
            Description: "Flags first-seen DNS domains whose full query name is unusually long and high-entropy, using baseline observations rather than free-text matching.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R095.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R095",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[]
            {
                "source", "dns.qname", "dns.queryLength", "dns.entropy",
                "baseline.reason", "baseline.observationCount", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "The queried domain must be first-seen for the source or globally novel in the in-process tracker.",
                "The full domain must be long and high-entropy."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "No match when baseline storage is unavailable.",
                "Do not infer newly observed domains from AnyText or host-only evidence."
            },
            minimumConfidence: 72,
            threshold: null,
            window: null,
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+domain",
            falsePositives: new[]
            {
                "Security sandboxes, malware labs, and synthetic replay traffic can introduce one-off random domains.",
                "Large SaaS or CDN vanity domains can be first-seen during onboarding and should be tuned with baseline history."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "EntropyThreshold", "MinimumQueryLength" },
            requiredTests: new[]
            {
                "positive first-seen high-entropy sample",
                "negative missing DNS telemetry",
                "negative AnyText-only sample",
                "evidence and confidence assertion"
            });

        public R095_NewlyObservedDomainWithHighEntropyRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("First-time software-update or SaaS onboarding domain", "Tune with a baseline warm-up period and approved domains rather than matching on domain text alone.")
        };

        protected override string? InvestigationHintOverride
            => "Confirm that the source host has not queried the domain before, review adjacent DNS answers and subsequent TLS/HTTP destinations, and validate whether a new application rollout explains the domain.";

        protected override string? TuningHintOverride
            => "Prefer tuning by known software-update roots and observation count. Keep the rule in Shadow while the baseline is still warming up.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            var root = RootDomain(query);
            if (LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(root))
                return NoMatch();

            var minimumLength = IntSetting(Descriptor.RuleId, "MinimumQueryLength", 32, 16, 255);
            if (query.Length < minimumLength)
                return NoMatch();

            var entropy = ShannonEntropy(query.Replace(".", string.Empty, StringComparison.Ordinal));
            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.75, 2.0, 8.0);
            if (entropy < entropyThreshold)
                return NoMatch();

            var baseline = ObserveBaseline("dns.high-entropy-domain", context.Record.Source ?? "unknown", query, context, $"qtype={context.Record.DnsQtype}");

            var firstSeenNow = FirstTimeSeen(query, context.TimestampUtc);
            if (!firstSeenNow && !baseline.IsFirstSeen)
                return NoMatch();

            var highSeverity = entropy >= entropyThreshold + 0.35 && query.Length >= minimumLength + 8;
            var matchedConditions = new List<string> { "first_seen_domain", "high_entropy_domain", "dns_qname_present" };
            if (highSeverity)
                matchedConditions.Add("exceptionally_random_long_domain");

            var whyMatched = $"The DNS domain '{query}' is first-seen for {context.Record.Source} and has unusually high entropy across the full query.";
            var severityReason = highSeverity
                ? "Severity is High because the domain is both novel and strongly random-looking, which is consistent with staged malware rendezvous or covert channels."
                : "Severity is Medium because the domain is novel and random-looking, but the evidence comes from a single first-seen DNS observation.";
            var falsePositives = "New SaaS onboarding, software updaters, and security tooling can introduce one-off random domains. Review baseline history before promoting the signal.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.queryLength", query.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("baseline.observationCount", baseline.ObservationCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "baseline"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Review the endpoint or workload that issued the DNS query and confirm whether a new application rollout explains the domain.",
                "Check subsequent DNS answers, TLS SNI, and HTTP destinations for the same root to determine whether the domain led to follow-on traffic.",
                "Allowlist only confirmed benign onboarding domains after baseline review."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"First-seen high-entropy DNS domain observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "high-domain-entropy");
                    confidence.AddEvidence(0.12, "long-query-name");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase))
                        confidence.AddBaseline(0.24, baseline.Reason);
                    else
                        confidence.AddCorrelation(0.12, "baseline-unavailable-fallback");
                    if (firstSeenNow) confidence.AddBaseline(0.10, "global-first-seen");
                    if (highSeverity) confidence.AddEvidence(0.14, "exceptionally-random-domain");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
