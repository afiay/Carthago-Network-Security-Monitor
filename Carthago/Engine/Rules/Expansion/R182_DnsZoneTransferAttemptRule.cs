// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R182_DnsZoneTransferAttemptRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R182_DnsZoneTransferAttemptRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R182",
            Name: "DNS Zone Transfer Attempt",
            Category: "DnsAdvanced",
            Description: "Detects structured AXFR or IXFR attempts that cross an internal/external boundary or target public-facing DNS infrastructure, rather than any text containing AXFR.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R182.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R182",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "dns_qname", "dns_qtype" },
            evidenceFields: new[] { "dns.qname", "dns.qtype", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured AXFR or IXFR DNS query.",
                "The traffic should cross an internal/external boundary or otherwise target non-private DNS infrastructure."
            },
            negativeConditions: new[]
            {
                "Do not alert on non-transfer qtypes.",
                "Do not alert on internal-only secondary replication telemetry when no boundary signal exists."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+query",
            falsePositives: new[] { "Legitimate secondary DNS replication can use AXFR or IXFR on trusted internal paths." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive boundary zone transfer sample", "negative internal secondary sample" });

        public R182_DnsZoneTransferAttemptRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!TryGetDnsQuestion(context, out var query))
                return NoMatch();

            var qtype = context.Record.DnsQtype ?? string.Empty;
            if (!string.Equals(qtype, "AXFR", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(qtype, "IXFR", StringComparison.OrdinalIgnoreCase))
            {
                return NoMatch();
            }

            var boundary = IsExternalDestination(context.Record.Destination) || IsExternalEndpoint(context.Record.Source);
            if (!boundary)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "zone_transfer_qtype,boundary_crossing", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS query used AXFR or IXFR and crossed an internal/external boundary, which is unusual outside trusted replication paths.",
                "Severity is High because zone transfer attempts can expose the full namespace and host inventory of a domain.",
                "Trusted secondary DNS replication can use the same qtypes. Validate whether the source and destination are approved authoritative servers.",
                "Confirm whether the source is an approved secondary DNS server.",
                "Review follow-on enumeration, reverse DNS, and SRV probing from the same source."));

            return MatchDns(
                context,
                SeverityLevel.High,
                $"DNS zone transfer attempt observed: {query}",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "zone-transfer-qtype");
                    confidence.AddEvidence(0.22, "boundary-crossing");
                },
                cooldownKey: $"{context.Record.Source}:{query}");
        }
    }
}
