// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R197_DnsRebindingPrivateIpAnswerRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R197_DnsRebindingPrivateIpAnswerRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R197",
            Name: "DNS Rebinding Private IP Answer",
            Category: "DnsAdvanced",
            Description: "Detects public-looking DNS responses that resolve to private or loopback IP space under rebinding-favored conditions, instead of flagging every split-horizon answer.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R197.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R197",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_answers" },
            evidenceFields: new[] { "dns.qname", "dns.answers", "dns.ttl", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured DNS response.",
                "The queried name must look public rather than internal-only.",
                "The answer set must contain a private or loopback IP under rebinding-favored conditions such as low TTL, loopback targets, or mixed public/private answers."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal-only namespaces.",
                "Do not alert on long-lived split-horizon answers that lack rebinding-style characteristics."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Some split-horizon DNS designs can answer public-looking names with private IPs, especially inside hybrid enterprise networks." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "MaxRebindingTtlSeconds" },
            requiredTests: new[] { "positive private answer with low ttl sample", "negative long ttl split horizon sample" });

        public R197_DnsRebindingPrivateIpAnswerRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !context.Record.DnsIsResponse || LooksLikeInternalOnlyDnsName(query))
                return NoMatch();

            if (!TryGetPrivateAnswerIp(context.Record.DnsAnswers, out var privateIp, out var loopbackOrLinkLocal, out var mixedPublicAndPrivate))
                return NoMatch();

            var maxTtl = IntSetting(Descriptor.RuleId, "MaxRebindingTtlSeconds", 60, 0, 3600);
            var lowTtl = context.Record.DnsTtl.HasValue && context.Record.DnsTtl.Value <= maxTtl;
            if (!lowTtl && !loopbackOrLinkLocal && !mixedPublicAndPrivate)
                return NoMatch();

            var matched = new List<string> { "private_answer_ip" };
            if (lowTtl) matched.Add("low_ttl");
            if (loopbackOrLinkLocal) matched.Add("loopback_or_linklocal_answer");
            if (mixedPublicAndPrivate) matched.Add("mixed_public_private_answers");

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.privateAnswer", privateIp, "dns"),
                new("matched_conditions", string.Join(",", matched), "rule")
            };
            evidence.AddRange(AnalystContext(
                "A public-looking DNS response resolved to private or loopback space under rebinding-favored conditions.",
                "Severity is High because low-TTL or mixed-answer private resolution can support browser-based DNS rebinding and local-network pivot attempts.",
                "Hybrid split-horizon designs can sometimes answer public names with private space legitimately. Validate TTL policy and resolver design before escalating.",
                "Review the resolved domain, TTL behavior, and any follow-on web sessions from affected endpoints.",
                "Confirm whether the domain is approved to resolve into private or loopback address space."));

            return MatchDns(
                context,
                SeverityLevel.High,
                $"DNS rebinding-style private answer observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "private-answer-ip");
                    if (lowTtl) confidence.AddEvidence(0.18, "low-ttl");
                    if (loopbackOrLinkLocal) confidence.AddEvidence(0.18, "loopback-or-linklocal-answer");
                    if (mixedPublicAndPrivate) confidence.AddEvidence(0.12, "mixed-public-private-answers");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
