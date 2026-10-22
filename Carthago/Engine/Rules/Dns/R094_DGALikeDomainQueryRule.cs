// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R094_DGALikeDomainQueryRule.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R094_DGALikeDomainQueryRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R094",
            Name: "DGA-Like Domain Query",
            Category: "Dns",
            Description: "Flags DNS questions whose second-level domain shape looks algorithmically generated based on label entropy, vowel scarcity, digit mix, and DNS field evidence.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R094.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R094",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[]
            {
                "source", "dns.qname", "dns.sld", "dns.entropy", "dns.vowelRatio", "dns.digitRatio",
                "baseline.reason", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS qname must be present in structured DNS telemetry.",
                "The second-level label must be long, high-entropy, and vowel-sparse.",
                "Known benign validation or platform telemetry roots must be excluded."
            },
            negativeConditions: new[]
            {
                "No match when DNS qname telemetry is absent.",
                "Do not infer a DNS query from AnyText, generic host strings, or port 53 alone.",
                "Suppress repeated hits from the same source/root combination during cooldown."
            },
            minimumConfidence: 78,
            threshold: null,
            window: null,
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+root_domain",
            falsePositives: new[]
            {
                "Malware sandboxes, DNS sinkholes, or security products can generate high-entropy labels.",
                "Some CDN or software telemetry domains can look random and should be allowlisted before promoting noise-sensitive environments."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "EntropyThreshold", "MinimumSecondLevelLength" },
            requiredTests: new[]
            {
                "positive strong DNS sample",
                "negative missing DNS telemetry",
                "negative AnyText-only sample",
                "evidence and confidence assertion"
            });

        public R094_DGALikeDomainQueryRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("Endpoint security or malware-analysis tooling generates pseudo-random domains", "Allowlist the resolver, process name, or known vendor root before suppressing the rule entirely.")
        };

        protected override string? InvestigationHintOverride
            => "Review the exact DNS qname, the querying host/process, recent sibling domains from the same source, and any related TLS or HTTP destinations for the same root.";

        protected override string? TuningHintOverride
            => "Tune entropy and minimum-label-length thresholds with known software-update, telemetry, and security-product domains rather than allowing generic hostname text.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            var root = RootDomain(query);
            if (LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(root))
                return NoMatch();

            var secondLevelLabel = SecondLevelLabel(query);
            if (LooksLikePunycodeLabel(secondLevelLabel))
                return NoMatch();

            if (secondLevelLabel.Length < IntSetting(Descriptor.RuleId, "MinimumSecondLevelLength", 14, 8, 63))
                return NoMatch();

            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.25, 2.0, 8.0);
            var entropy = ShannonEntropy(secondLevelLabel);
            var vowelRatio = VowelRatio(secondLevelLabel);
            var digitRatio = DigitRatio(secondLevelLabel);
            if (entropy < entropyThreshold || vowelRatio > 0.32 || digitRatio < 0.10)
                return NoMatch();

            var baseline = ObserveBaseline("dns.dga-candidate", context.Record.Source ?? "unknown", query, context, $"qtype={context.Record.DnsQtype}");
            if (baseline.IsKnown && baseline.ObservationCount >= 3)
                return NoMatch();

            var matchedConditions = new List<string> { "high_sld_entropy", "low_vowel_ratio", "digit_mixture", "dns_qname_present" };
            if (secondLevelLabel.Length >= 18)
                matchedConditions.Add("long_second_level_label");
            if (string.Equals(context.Record.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                || string.Equals(context.Record.DnsQtype, "AAAA", StringComparison.OrdinalIgnoreCase)
                || string.Equals(context.Record.DnsQtype, "TXT", StringComparison.OrdinalIgnoreCase))
            {
                matchedConditions.Add("resolution_or_txt_query_type");
            }

            var whyMatched = $"The second-level label '{secondLevelLabel}' is unusually long and random-looking for a DNS question from {context.Record.Source}.";
            var severityReason = "Severity is High because the match is based on structured DNS qname features rather than host text, and the label satisfies multiple DGA-shape signals at once.";
            var falsePositives = "Software telemetry, security products, and sinkholes can generate random-looking labels. Review the source process and any known vendor roots before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.sld", secondLevelLabel, "dns"),
                new("dns.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.vowelRatio", vowelRatio.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.digitRatio", digitRatio.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("baseline.reason", baseline.Reason, "baseline"),
                new("baseline.observationCount", baseline.ObservationCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "baseline"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect the querying process or endpoint owner for suspicious scheduled tasks, scripts, or recently started binaries.",
                "Pivot to sibling domains and adjacent TLS/HTTP connections for the same root or destination ASN.",
                "Allowlist only known vendor or sinkhole roots after confirming the activity is expected."));

            return MatchDns(
                context,
                SeverityLevel.High,
                $"DGA-like DNS query observed for {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.36, "high-sld-entropy");
                    confidence.AddEvidence(0.16, "low-vowel-ratio");
                    confidence.AddEvidence(0.10, "digit-mixture");
                    if (secondLevelLabel.Length >= 18) confidence.AddEvidence(0.12, "long-sld");
                    if (matchedConditions.Contains("resolution_or_txt_query_type", StringComparer.OrdinalIgnoreCase)) confidence.AddCorrelation(0.08, "supported-query-type");
                    if (!string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase))
                        confidence.AddBaseline(baseline.IsFirstSeen || !baseline.IsKnown ? 0.16 : 0.08, baseline.Reason);
                    else
                        confidence.AddCorrelation(0.08, "baseline-unavailable-fallback");
                },
                cooldownKey: $"{context.Record.Source}:{root}");
        }
    }
}
