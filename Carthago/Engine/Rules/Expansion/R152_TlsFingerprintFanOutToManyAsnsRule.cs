// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R152_TlsFingerprintFanOutToManyAsnsRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R152_TlsFingerprintFanOutToManyAsnsRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R152",
            Name: "TLS Fingerprint Fan-Out To Many ASNs",
            Category: "TlsPki",
            Description: "Detects non-browser external TLS fingerprints that fan out to many distinct ASNs in a short window.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R152.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R152",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls, RuleTelemetryKind.Ja3, RuleTelemetryKind.Ja4, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "tls_any", "tls_fingerprint_or_sni" },
            evidenceFields: new[] { "matched_conditions", "count", "whois.asn" },
            positiveConditions: new[]
            {
                "The record must contain a TLS fingerprint and ASN enrichment.",
                "The destination must be external.",
                "The same non-browser fingerprint must reach many distinct ASNs within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on browser-like traffic.",
                "Do not alert on low fan-out to only a few ASNs."
            },
            minimumConfidence: 74,
            threshold: 5,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "asn",
            falsePositives: new[]
            {
                "Content delivery clients, package managers, and broadly distributed enterprise agents can reach many ASNs with the same fingerprint."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive tls fingerprint fanout sample",
                "negative browser fanout sample"
            });

        public R152_TlsFingerprintFanOutToManyAsnsRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var fingerprint = string.IsNullOrWhiteSpace(record.Ja4) ? record.Ja3 : record.Ja4;
            if (!IsTls(record)
                || string.IsNullOrWhiteSpace(host)
                || string.IsNullOrWhiteSpace(fingerprint)
                || string.IsNullOrWhiteSpace(record.WhoisASN)
                || !IsExternalAddress(host)
                || IsLikelyBrowserProcess(record.ProcessName))
            {
                return NoMatch();
            }

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 5, 3, 200);
            var distinctAsns = CountDistinctValues($"{Rule.RuleId}:{fingerprint}", record.WhoisASN!, context.TimestampUtc, window);
            if (distinctAsns < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,fingerprint_fanout_many_asns", "rule"),
                new("count", distinctAsns.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("whois.asn", record.WhoisASN!, "whois")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-browser TLS fingerprint reached many distinct ASNs in a short time window.",
                "Severity is Medium because broad ASN fan-out with a stable uncommon client fingerprint can indicate automated distribution, scanning, or C2 infrastructure discovery.",
                "Package managers, distributed agents, and some enterprise automation can look similar. Validate whether the process and destinations are expected.",
                "Review whether the fingerprint belongs to an approved enterprise client or package manager.",
                "Inspect the ASN distribution and whether the same source also fans out across unusual domains or ports."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "TLS fingerprint fanned out across many ASNs",
                "FingerprintFanoutAsn",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-fingerprint");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "asn-fanout-threshold");
                },
                distinctAsns,
                window,
                fingerprint);
        }
    }
}
