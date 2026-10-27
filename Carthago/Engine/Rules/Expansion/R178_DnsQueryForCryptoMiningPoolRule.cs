// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R178_DnsQueryForCryptoMiningPoolRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R178_DnsQueryForCryptoMiningPoolRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R178",
            Name: "DNS Query For Crypto Mining Pool",
            Category: "DnsAdvanced",
            Description: "Detects DNS questions to known mining pool infrastructure when the queried name carries pool-like semantics, rather than matching any cryptocurrency-related hostname text.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R178.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R178",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "dns.rootDomain", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "The qname must resolve beneath a known mining pool root.",
                "The left labels must look like pool or stratum infrastructure rather than a generic brand website visit."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only matches without DNS telemetry.",
                "Do not alert on unrelated cryptocurrency-branded hostnames outside known pool roots."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+root",
            falsePositives: new[] { "Approved research systems or sanctioned mining infrastructure can query pool domains legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive mining pool dns sample", "negative generic crypto brand sample" });

        public R178_DnsQueryForCryptoMiningPoolRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !IsMiningPoolQuery(query) || !HasExplicitMiningPoolSignal(query) || !_replay.Observe(context.Record, context.TimestampUtc))
                return NoMatch();

            var root = RootDomain(query);
            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "known_pool_root,pool_like_subdomain", "rule"),
                new("dns.poolRoot", root, "dns")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question targeted a known mining-pool root and the host looked like stratum or pool infrastructure rather than a casual brand page.",
                "Severity is High because mining pool DNS often indicates unauthorized cryptomining, mining malware, or deliberate policy bypass.",
                "Security labs or sanctioned mining research can generate similar lookups. Validate device role and approved use before escalating.",
                "Review the querying process and any follow-on TLS connections to the resolved host.",
                "Confirm whether the endpoint is approved to use mining-related infrastructure."));

            return MatchDns(
                context,
                SeverityLevel.High,
                "Mining-pool DNS query observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "known-pool-root");
                    confidence.AddEvidence(0.24, "pool-like-subdomain");
                },
                cooldownKey: $"{context.Record.Source}:{root}");
        }
    }
}
