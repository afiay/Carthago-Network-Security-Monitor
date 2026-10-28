// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R186_DnsCaaRecordProbingBurstRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R186_DnsCaaRecordProbingBurstRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R186",
            Name: "DNS CAA Record Probing Burst",
            Category: "DnsAdvanced",
            Description: "Detects bursts of CAA lookups across many distinct roots instead of isolated certificate-validation style queries.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R186.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R186",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname", "dns_qtype" },
            evidenceFields: new[] { "dns.qname", "count", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must be a structured CAA query.",
                "The same source must query many distinct roots within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on isolated CAA lookups.",
                "Do not alert on low-volume certificate-validation traffic."
            },
            minimumConfidence: 68,
            threshold: 8,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "root_domain",
            falsePositives: new[] { "Certificate validation services, ACME tooling, and PKI research can legitimately query many CAA records." },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[] { "positive caa burst sample", "negative isolated caa sample" });

        public R186_DnsCaaRecordProbingBurstRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !string.Equals(context.Record.DnsQtype, "CAA", StringComparison.OrdinalIgnoreCase))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var threshold = IntSetting(Descriptor.RuleId, "Threshold", 8, 3, 100);
            var count = _window.Observe(context.Record, $"{Descriptor.RuleId}:{context.Record.Source}:{context.Record.Destination}", RootDomain(query), context.TimestampUtc, window, distinct: true);
            if (count < threshold)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", "caa_query,distinct_root_threshold", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The same source queried CAA records across many distinct roots in a short window.",
                "Severity is Low because this pattern can indicate discovery of certificate issuance policy, but it is also common in PKI tooling.",
                "ACME services, PKI inventory, and certificate research can generate similar bursts.",
                "Confirm whether the source is an approved PKI or certificate management system.",
                "Review whether the source is also probing MX, TXT, or DNSSEC records for the same domains."));

            return MatchDns(
                context,
                SeverityLevel.Low,
                "CAA probing burst observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.16, "caa-query");
                    confidence.AddEvidence(0.18, "distinct-root-threshold");
                },
                count,
                window,
                 $"{context.Record.Source}:{context.Record.Destination}");
        }
    }
}
