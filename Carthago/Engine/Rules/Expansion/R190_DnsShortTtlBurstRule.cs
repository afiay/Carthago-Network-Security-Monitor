// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R190_DnsShortTtlBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R190_DnsShortTtlBurstRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R190",
            Name: "DNS Short TTL Burst",
            Category: "DnsAdvanced",
            Description: "Detects bursts of very low-TTL DNS responses for non-approved roots instead of single short-TTL answers that can occur legitimately.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R190.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R190",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_ttl" },
            evidenceFields: new[] { "dns.qname", "dns.ttl", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured DNS response with a very short TTL.",
                "The root should not be a known telemetry or CDN provider.",
                "The same source and root must repeat this pattern within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on higher TTL values.",
                "Do not alert on isolated short-TTL responses for approved telemetry or delivery networks."
            },
            minimumConfidence: 72,
            threshold: 6,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+root",
            falsePositives: new[] { "Some CDN and failover systems legitimately use low TTL values; approved roots should be tuned rather than globally disabled." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "MaxTtlSeconds" },
            requiredTests: new[] { "positive repeated short ttl sample", "negative high ttl sample" });

        public R190_DnsShortTtlBurstRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch186190Evidence.DnsResponse(context.Record, out var query))
                return NoMatch();

            var maxTtl = IntSetting(Descriptor.RuleId, "MaxTtlSeconds", 1, 0, 30);
            if (context.Record.DnsTtl.Value > maxTtl || IsKnownTelemetryRoot(RootDomain(query)))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 300, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 6, 3, 100);
            var root = RootDomain(query);
            var count = _window.Observe(context.Record, $"{Descriptor.RuleId}:{context.Record.Destination}:{context.Record.Source}:{root}", query, context.TimestampUtc, window, distinct: false);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "dns_response,very_short_ttl,threshold_reached", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source observed repeated very short-TTL DNS responses for the same root in a short window.",
                "Severity is Medium because aggressive short TTLs can support fast-flux, rebinding, or unstable beacon infrastructure when they repeat outside approved roots.",
                "Some failover and delivery systems use low TTLs legitimately. Validate root ownership and service design before escalating.",
                "Review answer-set churn, private-IP rebinding signals, and follow-on connections to the resolved hosts.",
                "Confirm whether the root is an approved CDN, failover, or telemetry service."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                "Short-TTL DNS burst observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "dns-response");
                    confidence.AddEvidence(0.18, "very-short-ttl");
                    confidence.AddEvidence(0.18, "threshold-reached");
                },
                count,
                window,
                $"{context.Record.Destination}:{context.Record.Source}:{root}");
        }
    }
}
