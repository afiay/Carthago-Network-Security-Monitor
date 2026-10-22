// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R096_FastFluxDNSPatternRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R096_FastFluxDNSPatternRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R096",
            Name: "Fast-Flux DNS Pattern",
            Category: "Dns",
            Description: "Flags DNS responses that return many public IP answers with unusually low TTL values, consistent with fast-flux-style rotation rather than host text matching.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R096.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R096",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "dns_qname", "destination_or_host" },
            evidenceFields: new[]
            {
                "dns.qname", "dns.answers", "dns.answerCount", "dns.ttl", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS response with answers and TTL data must be present.",
                "The answer set must contain multiple distinct IPs.",
                "TTL must be low enough to indicate rapid answer churn."
            },
            negativeConditions: new[]
            {
                "No match when answer or TTL telemetry is absent.",
                "Do not infer fast flux from ports or protocol labels alone.",
                "Suppress likely CDN or platform domains unless the answer churn is extreme."
            },
            minimumConfidence: 76,
            threshold: 4,
            window: null,
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "domain",
            falsePositives: new[]
            {
                "CDN and global traffic-steering services can legitimately return many IPs with low TTL values.",
                "Security sinkholes and DDoS protection services may rotate answers aggressively."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "Threshold", "MaximumTtlSeconds" },
            requiredTests: new[]
            {
                "positive fast-flux DNS response sample",
                "negative missing DNS answer telemetry",
                "negative port-only sample",
                "evidence and confidence assertion"
            });

        public R096_FastFluxDNSPatternRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("CDN, WAF, or anycast-backed domains", "Allowlist well-known provider roots and require larger answer sets before promoting the rule to paging alerting.")
        };

        protected override string? InvestigationHintOverride
            => "Check whether the queried root belongs to an expected CDN or security provider, and correlate with subsequent connections to the returned IPs.";

        protected override string? TuningHintOverride
            => "Tune by approved CDN/security roots and TTL threshold, not by generic host text. Keep fast-flux alerting focused on non-approved destinations.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            if (!context.Record.DnsIsResponse || string.IsNullOrWhiteSpace(context.Record.DnsAnswers) || !context.Record.DnsTtl.HasValue)
                return NoMatch();

            var answerCount = CountAnswerIps(context.Record.DnsAnswers);
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 4, 2, 32);
            var maximumTtl = IntSetting(Descriptor.RuleId, "MaximumTtlSeconds", 120, 10, 3600);
            if (answerCount < threshold || context.Record.DnsTtl.Value <= 0 || context.Record.DnsTtl.Value > maximumTtl)
                return NoMatch();

            var root = RootDomain(query);
            if (IsKnownTelemetryRoot(root) && answerCount < threshold + 2)
                return NoMatch();

            var highSeverity = answerCount >= threshold + 2 || context.Record.DnsTtl.Value <= maximumTtl / 2;
            var matchedConditions = new List<string> { "multi_ip_dns_answer", "low_dns_ttl", "dns_response_context" };
            if (highSeverity)
                matchedConditions.Add("aggressive_answer_churn");

            var whyMatched = $"The DNS response for '{query}' returned {answerCount} distinct IPs with a TTL of {context.Record.DnsTtl.Value}s.";
            var severityReason = highSeverity
                ? "Severity is High because the answer set and TTL indicate rapid infrastructure rotation rather than a single noisy DNS answer."
                : "Severity is Medium because the pattern resembles fast flux, but the answer churn is not extreme enough for a high-fidelity alert.";
            var falsePositives = "CDNs, DDoS protection services, and sinkholes can rotate DNS answers quickly. Validate the domain owner and expected traffic path before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.answerCount", answerCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Verify whether the domain belongs to an approved CDN, WAF, or security sinkhole provider.",
                "Pivot to the returned IP addresses and inspect follow-on TLS/HTTP connections from the same source.",
                "Tune the threshold or approved roots only after confirming the pattern is benign in your environment."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Fast-flux-like DNS answer pattern observed for {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "multi-ip-answer-set");
                    confidence.AddEvidence(0.24, "low-dns-ttl");
                    if (highSeverity) confidence.AddEvidence(0.12, "aggressive-answer-churn");
                    if (!IsKnownTelemetryRoot(root)) confidence.AddCorrelation(0.08, "non-approved-root");
                },
                cooldownKey: root);
        }
    }
}
