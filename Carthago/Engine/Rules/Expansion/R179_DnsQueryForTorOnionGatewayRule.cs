// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R179_DnsQueryForTorOnionGatewayRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R179_DnsQueryForTorOnionGatewayRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R179",
            Name: "DNS Query For Tor Onion Gateway",
            Category: "DnsAdvanced",
            Description: "Detects DNS queries that target Tor onion gateway services or literal onion-style names instead of any occurrence of the word onion.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R179.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R179",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "The qname must match a known Tor onion gateway root or literal onion-style naming pattern."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only mentions of onion.",
                "Do not alert on unrelated hosts whose labels merely contain the string onion."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Threat-research systems and privacy tooling may deliberately test onion gateways." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive tor gateway query sample", "negative unrelated onion word sample" });

        public R179_DnsQueryForTorOnionGatewayRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query) || !IsTorGatewayQuery(query))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tor_gateway_or_onion_pattern", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question targeted a known Tor onion gateway or used a literal onion-style naming pattern.",
                "Severity is Medium because onion gateway DNS can indicate Tor browsing, privacy tooling, or staging for anonymous infrastructure.",
                "Approved research or privacy-focused systems may use Tor gateway services legitimately.",
                "Review the endpoint process and any follow-on HTTP or TLS traffic to the resolved destination.",
                "Confirm whether Tor gateway use is allowed for the device or user."));

            return MatchDns(
                context,
                SeverityLevel.Medium,
                $"Tor onion gateway DNS query observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "tor-gateway-or-onion-pattern");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
