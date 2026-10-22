// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R189_AdSrvQueryToExternalResolverRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R189_AdSrvQueryToExternalResolverRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R189",
            Name: "AD SRV Query To External Resolver",
            Category: "DnsAdvanced",
            Description: "Detects Active Directory SRV lookups sent to external resolvers, focusing on internal namespace leakage rather than ordinary public SRV traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R189.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R189",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Flow, RuleTelemetryKind.Identity },
            requiredFields: new[] { "source", "destination_or_host", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "resolver.destination", "matched_conditions" },
            positiveConditions: new[]
            {
                "The query must be a structured AD SRV lookup.",
                "The resolver destination must be external.",
                "The queried AD SRV namespace should look internal or _msdcs-scoped."
            },
            negativeConditions: new[]
            {
                "Do not alert on internal resolver paths.",
                "Do not alert on unrelated public SRV queries."
            },
            minimumConfidence: 84,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+resolver",
            falsePositives: new[] { "Misconfigured split-DNS or test environments can leak AD SRV queries outward unintentionally." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive ad srv leak to external resolver sample", "negative public srv query sample" });

        public R189_AdSrvQueryToExternalResolverRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !IsAdSrvQuery(query) || !IsExternalDestination(context.Record.Destination))
                return NoMatch();

            var internalNamespace = LooksLikeInternalOnlyDnsName(query) || query.Contains("._msdcs.", StringComparison.OrdinalIgnoreCase);
            if (!internalNamespace)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("resolver.destination", context.Record.Destination ?? "unknown", "dns"),
                new("matched_conditions", "ad_srv_query,external_resolver,internal_namespace", "rule")
            };
            evidence.AddRange(AnalystContext(
                "An Active Directory SRV lookup for an internal-style namespace was sent to an external resolver.",
                "Severity is High because this leaks AD discovery intent and can expose internal namespace structure to third-party DNS infrastructure.",
                "Split-DNS misconfiguration or roaming clients can create this pattern unintentionally.",
                "Confirm whether the endpoint is using an approved internal resolver.",
                "Review the host's DNS settings, VPN state, and any additional internal-name leaks."));

            return MatchDns(
                context,
                SeverityLevel.High,
                $"AD SRV query leaked to external resolver: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "ad-srv-query");
                    confidence.AddEvidence(0.24, "external-resolver");
                    confidence.AddEvidence(0.16, "internal-namespace");
                },
                cooldownKey: $"{context.Record.Source}:{context.Record.Destination}");
        }
    }
}
