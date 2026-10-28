// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R195_DnsOverTlsToUnapprovedResolverRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R195_DnsOverTlsToUnapprovedResolverRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly string[] ApprovedDotHosts =
        {
            "cloudflare-dns.com", "dns.google", "dns.quad9.net", "dns.adguard-dns.com",
            "family.adguard-dns.com", "dns.nextdns.io", "one.one.one.one"
        };

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R195",
            Name: "DNS Over TLS To Unapproved Resolver",
            Category: "DnsAdvanced",
            Description: "Detects external DNS-over-TLS sessions on port 853 when the resolver host is not approved, instead of relying on port-only heuristics.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R195.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R195",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort", "tls.host" },
            positiveConditions: new[]
            {
                "The record must have concrete TLS context for a DNS-over-TLS style connection on port 853.",
                "The destination must be external.",
                "The resolver host must not be part of the approved DoT list."
            },
            negativeConditions: new[]
            {
                "Do not alert on approved public or enterprise DoT resolvers.",
                "Do not alert on ordinary TLS sessions that happen to contain DNS strings without DoT port context."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Enterprises may intentionally use custom private DoT resolvers; tune approved hosts rather than disabling the rule." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive unapproved dot resolver sample", "negative approved dot resolver sample" });

        public R195_DnsOverTlsToUnapprovedResolverRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch191195Evidence.Dot(record, out var host)
                || IsApprovedDotHost(host) || IsLikelyBrowserProcess(record.ProcessName)
                || !_replay.Observe(record, context.TimestampUtc))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tcp_853,tls_handshake,sni,external_destination,unapproved_resolver", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A TCP/853 TLS session with parsed handshake metadata and SNI targeted an external endpoint not on the static DoT resolver list; encrypted DNS payload was not inspected.",
                "Severity is High because unapproved DoT can bypass enterprise DNS controls while remaining opaque to traditional DNS telemetry.",
                "Some environments intentionally use custom private DoT resolvers. Validate resolver ownership before escalating.",
                "Review the endpoint process and any companion DoH or unusual DNS activity from the same source.",
                "Confirm whether the resolver host is approved for encrypted DNS use."));

            return MatchTls(
                context,
                SeverityLevel.High,
                "Unapproved DNS-over-TLS resolver observed",
                "DnsOverTls",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "dot-port-or-service");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.22, "unapproved-resolver");
                },
                cooldownKey: $"{record.Source}:{NetworkBatch166170Evidence.Key(host)}");
        }

        private static bool IsApprovedDotHost(string host)
        {
            foreach (var approved in ApprovedDotHosts)
            {
                if (host.Equals(approved, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + approved, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
