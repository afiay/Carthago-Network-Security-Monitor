// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/R101_DNSCNAMEChainAbuseRule.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Dns
{
    public sealed class R101_DNSCNAMEChainAbuseRule : DnsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R101",
            Name: "DNS CNAME Chain Abuse",
            Category: "Dns",
            Description: "Flags unusually deep DNS CNAME chains in actual response telemetry, while suppressing common CDN-style aliasing unless the chain depth is excessive.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R101.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R101",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "dns_qname", "dns_qtype" },
            evidenceFields: new[]
            {
                "dns.qname", "dns.answers", "dns.cnameCount", "dns.answerChainKnownProvider", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "A DNS response with answer telemetry must be present.",
                "The answer set must contain an unusually deep CNAME chain.",
                "Known CDN or platform aliasing should be filtered unless the chain is excessive even after provider-aware suppression."
            },
            negativeConditions: new[]
            {
                "No match when DNS response answers are absent.",
                "Do not infer CNAME abuse from destination host text.",
                "Suppress likely CDN aliasing unless the chain depth is extreme."
            },
            minimumConfidence: 68,
            threshold: 3,
            window: null,
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "domain",
            falsePositives: new[]
            {
                "CDNs, email-security products, and SaaS providers can legitimately use chained aliases.",
                "Platform migration windows may temporarily increase alias depth."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cname-chain sample",
                "negative missing answer telemetry",
                "negative AnyText-only sample",
                "evidence and confidence assertion"
            });

        public R101_DNSCNAMEChainAbuseRule()
            : base(Rule, Profile)
        {
        }

        protected override IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => new[]
        {
            new RuleFalsePositiveNote("CDN and SaaS alias depth", "Raise the chain threshold or allowlist well-known provider roots instead of disabling the rule.")
        };

        protected override string? InvestigationHintOverride
            => "Review the full DNS answer chain, determine whether it lands on an approved CDN or SaaS provider, and check whether the chain depth is new for the root.";

        protected override string? TuningHintOverride
            => "Tune with chain-depth thresholds and approved provider roots. Keep the rule grounded in DNS response answers, not free-text aliases.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            if (!context.Record.DnsIsResponse || string.IsNullOrWhiteSpace(context.Record.DnsAnswers))
                return NoMatch();

            var cnameCount = CountCnames(context.Record.DnsAnswers);
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 3, 2, 20);
            if (cnameCount < threshold)
                return NoMatch();

            var root = RootDomain(query);
            var answerChainKnownProvider = AnswerSetContainsKnownTelemetryRoot(context.Record.DnsAnswers);
            if ((IsKnownTelemetryRoot(root) || answerChainKnownProvider) && cnameCount < threshold + 2)
                return NoMatch();

            var highSeverity = cnameCount >= threshold + 2 || context.Record.DnsAnswers.Count(character => character == '>') >= threshold + 1;
            var matchedConditions = new List<string> { "dns_response_context", "cname_chain_depth" };
            if (highSeverity)
                matchedConditions.Add("excessive_alias_depth");
            if (answerChainKnownProvider)
                matchedConditions.Add("provider_aware_suppression_bypassed");

            var whyMatched = $"The DNS response for '{query}' contains {cnameCount} chained CNAME records.";
            var severityReason = highSeverity
                ? "Severity is High because the alias chain is deeper than normal provider aliasing and can hide staging, cloaking, or redirect infrastructure."
                : "Severity is Medium because multiple CNAMEs are present, but the depth may still overlap with legitimate CDN behavior.";
            var falsePositives = "CDN, email, and SaaS providers often use chained aliases. Validate the provider and whether the chain depth is normal for the environment.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("dns.cnameCount", cnameCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"),
                new("dns.answerChainKnownProvider", answerChainKnownProvider ? "true" : "false", "dns"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect the full answer chain and determine whether it terminates on an approved CDN or service.",
                "Compare the observed alias depth with previous responses for the same root.",
                "Tune by approved provider roots or a higher chain threshold if the environment relies on deep aliasing."));

            return MatchDns(
                context,
                highSeverity ? SeverityLevel.High : SeverityLevel.Medium,
                $"Deep DNS CNAME chain observed for {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "cname-chain-depth");
                    if (highSeverity) confidence.AddEvidence(0.18, "excessive-alias-depth");
                    if (!IsKnownTelemetryRoot(root) && !answerChainKnownProvider) confidence.AddCorrelation(0.12, "non-approved-root");
                    confidence.AddEvidence(0.08, "dns-response-answer-context");
                },
                cooldownKey: root);
        }
    }
}
