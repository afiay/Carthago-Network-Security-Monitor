// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R180_DnsQueryToHighRiskTldRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R180_DnsQueryToHighRiskTldRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R180",
            Name: "DNS Query To High-Risk TLD",
            Category: "DnsAdvanced",
            Description: "Detects first-seen or unusually shaped DNS queries under historically risky TLDs instead of alerting on every domain under those TLDs.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R180.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R180",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "baseline.reason", "dns.entropy", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present under a high-risk TLD.",
                "The domain should be first-seen or visibly suspicious in shape, such as long or entropy-heavy second-level labels.",
                "Common, human-readable domains should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only mentions of high-risk TLDs.",
                "Do not alert on common short domains under those TLDs when no first-seen or suspicious-shape signal exists."
            },
            minimumConfidence: 68,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+tld",
            falsePositives: new[] { "Some modern legitimate sites use .zip, .xyz, or similar TLDs; validate domain ownership before escalating." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "EntropyThreshold", "MinimumLabelLength" },
            requiredTests: new[] { "positive first-seen risky tld sample", "negative short human domain sample" });

        public R180_DnsQueryToHighRiskTldRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !IsHighRiskTldQuery(query) || LooksLikeBenignValidationQuery(query) || IsKnownTelemetryRoot(RootDomain(query)))
                return NoMatch();

            var secondLevel = SecondLevelLabel(query);
            var entropyThreshold = DoubleSetting(Descriptor.RuleId, "EntropyThreshold", 2.9, 1.0, 8.0);
            var minimumLength = IntSetting(Descriptor.RuleId, "MinimumLabelLength", 9, 4, 63);
            var entropy = ShannonEntropy(secondLevel);
            var suspiciousShape = secondLevel.Length >= minimumLength && (entropy >= entropyThreshold || DigitRatio(secondLevel) >= 0.10);
            var baseline = ObserveBaseline("dns.high-risk-tld", context.Record.Source ?? "unknown", query, context, $"tld={TopLevelDomain(query)}");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen(query, context.TimestampUtc);
            var elevatedFirstSeen = firstSeen && secondLevel.Length >= minimumLength;
            if (!suspiciousShape && !elevatedFirstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("dns.entropy", entropy.ToString("F2", System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("matched_conditions", $"{(elevatedFirstSeen ? "first_seen," : string.Empty)}high_risk_tld{(suspiciousShape ? ",suspicious_second_level" : string.Empty)}".Trim(','), "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question used a high-risk TLD and was either first-seen or unusually shaped for a low-reputation naming pattern.",
                "Severity is Low because TLD risk alone is weak, but first-seen or entropy-heavy labels make the domain more investigation-worthy.",
                "Legitimate modern services may use .xyz, .zip, or similar TLDs. Validate ownership and business context before escalating.",
                "Check whether the domain is newly observed for this source or environment.",
                "Review follow-on web or TLS activity to the resolved destination."));

            if (!_replay.Observe(context.Record, context.TimestampUtc)) return NoMatch();

            return MatchDns(
                context,
                SeverityLevel.Low,
                "High-risk TLD DNS query observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "high-risk-tld");
                    if (suspiciousShape) confidence.AddEvidence(0.12, "suspicious-second-level");
                    if (firstSeen && !string.Equals(baseline.Reason, "baseline unavailable", StringComparison.OrdinalIgnoreCase)) confidence.AddBaseline(0.16, baseline.Reason);
                    else if (firstSeen) confidence.AddCorrelation(0.10, "first-seen-fallback");
                },
                cooldownKey: $"{context.Record.Source}:{TopLevelDomain(query)}");
        }
    }
}
