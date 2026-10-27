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

        private readonly NetworkBatch146152AsnWindow _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var fingerprint = NetworkBatch141145Evidence.Fingerprint(record);
            var asn = NetworkBatch146152Evidence.Asn(record);
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || fingerprint == null || asn == null
                || !NetworkBatch136140Evidence.ExternalDestination(record)
                || IsLikelyBrowserProcess(record.ProcessName))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 5, 3, 200);
            var key = $"{record.Source}:{fingerprint}";
            if (!_observations.Observe(key, record.Id, asn, context.TimestampUtc, window, out var distinctAsns)
                || distinctAsns < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "attributed_tls_tcp,external_socket,independent_distinct_asns", "rule"),
                new("count", distinctAsns.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("whois.asn", asn, "whois")
            };
            evidenceItems.AddRange(AnalystContext(
                "One source's TLS fingerprint reached multiple separately attributed ASNs within the configured window.",
                "Severity is Medium because rapid ASN fan-out may warrant review of automated outbound infrastructure.",
                "ASN enrichment can be stale or misleading. CDNs and software-updaters can reach many ASNs.",
                "Validate destination-to-ASN mapping and time-aligned enrichment.",
                "Check client ownership and approved distribution topology."));
            return MatchTls(context, SeverityLevel.Medium,
                "TLS fingerprint reached multiple independently observed ASNs",
                "FingerprintFanoutAsn", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-fingerprint");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "asn-fanout-threshold");
                }, distinctAsns, window,
                NetworkBatch136140Evidence.Fingerprint(key));
        }
    }
}
