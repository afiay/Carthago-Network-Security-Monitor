// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R191_ConsonantHeavyDgaDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R191_ConsonantHeavyDgaDomainRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R191",
            Name: "Consonant-Heavy DGA Domain",
            Category: "DnsAdvanced",
            Description: "Detects consonant-heavy, entropy-rich structured DNS names that resemble algorithmic generation rather than human-readable domains.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R191.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R191",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "dns.entropy", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "The second-level label must be consonant-heavy, sufficiently long, and entropy-rich.",
                "Punycode and obvious benign validation names should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on punycode or clearly human-readable domains.",
                "Do not alert on AnyText-only mentions of random-looking names."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Security research and generated lab domains can resemble DGA output." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "EntropyThreshold", "VowelRatioThreshold", "MinimumLabelLength" },
            requiredTests: new[] { "positive consonant-heavy dga sample", "negative human-readable domain sample" });

        public R191_ConsonantHeavyDgaDomainRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(RootDomain(query)))
                return NoMatch();

            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.0, 1.0, 8.0);
            var vowelRatioThreshold = DoubleSetting(Descriptor.RuleId, "VowelRatioThreshold", 0.18, 0.0, 1.0);
            var minimumLength = IntSetting(Descriptor.RuleId, "MinimumLabelLength", 10, 4, 63);
            if (!LooksConsonantHeavyDga(query, entropyThreshold, vowelRatioThreshold, minimumLength)
                || !_replay.Observe(context.Record, context.TimestampUtc))
                return NoMatch();

            var secondLevel = SecondLevelLabel(query);
            var entropy = ShannonEntropy(secondLevel);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("matched_conditions", "consonant_heavy_second_level,high_entropy", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question used a long second-level label with high consonant density and high entropy, which is atypical for human-readable naming.",
                "Severity is Medium because this pattern is consistent with DGA-style rendezvous or disposable infrastructure discovery.",
                "Research tooling and generated lab domains can look similar. Validate destination ownership and follow-on traffic before escalating.",
                "Review whether the host also queried newly observed, short-TTL, or NXDOMAIN-heavy domains.",
                "Inspect any follow-on TLS or HTTP sessions to the resolved destination."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                "Consonant-heavy DGA-like DNS query observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "consonant-heavy-second-level");
                    confidence.AddEvidence(0.18, "high-entropy");
                },
                cooldownKey: $"{context.Record.Source}:{NetworkBatch166170Evidence.Key(query)}");
        }
    }
}
