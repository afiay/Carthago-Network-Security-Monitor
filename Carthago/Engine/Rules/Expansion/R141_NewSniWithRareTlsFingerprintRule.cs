// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R141_NewSniWithRareTlsFingerprintRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R141_NewSniWithRareTlsFingerprintRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R141",
            Name: "New SNI With Rare TLS Fingerprint",
            Category: "TlsPki",
            Description: "Detects repeated external TLS sessions where a non-browser fingerprint repeatedly reaches the same SNI in a short window.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R141.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R141",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls, RuleTelemetryKind.Ja3, RuleTelemetryKind.Ja4, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "tls_any", "tls_fingerprint_or_sni" },
            evidenceFields: new[] { "matched_conditions", "count", "tls.sni" },
            positiveConditions: new[]
            {
                "The record must contain SNI and TLS fingerprint context.",
                "The destination must be external.",
                "The same fingerprint-to-SNI pair must repeat within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on browser-like TLS traffic.",
                "Do not alert on single one-off observations."
            },
            minimumConfidence: 74,
            threshold: 3,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Custom enterprise clients and niche SaaS agents can create stable but uncommon fingerprints. Validate whether the process and host are approved."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive repeated rare fingerprint sample",
                "negative browser tls sample"
            });

        public R141_NewSniWithRareTlsFingerprintRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch141145Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = NetworkBatch141145Evidence.Sni(record);
            var fingerprint = NetworkBatch141145Evidence.Fingerprint(record);
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || host == null || fingerprint == null
                || !NetworkBatch136140Evidence.ExternalDestination(record)
                || IsLikelyBrowserProcess(record.ProcessName))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 50);
            var key = $"{record.Source}:{fingerprint}:{host}";
            if (!_observations.Observe(key, record.Id, context.TimestampUtc, window, out var count)
                || count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "observed_tls_tcp,external_destination,distinct_repeated_fingerprint_sni", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("tls.sni", host, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "Distinct TLS/TCP observations from one client repeatedly used the same fingerprint and external SNI.",
                "Severity is Medium because repeated fingerprint/SNI pairing may warrant C2 triage; rarity and first-seen status are not established by this detector.",
                "Approved agents can maintain stable fingerprints. Confirm process ownership and endpoint authorization.",
                "Correlate the fingerprint with baseline frequency and approved outbound services.",
                "Inspect process lineage and independent destination reputation before escalation."));

            return MatchTls(context, SeverityLevel.Medium,
                "Repeated client TLS fingerprint observed against external SNI",
                "RareFingerprintSni", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "tls-fingerprint");
                    confidence.AddEvidence(0.20, "external-destination");
                    confidence.AddEvidence(0.18, "threshold-reached");
                }, count, window,
                NetworkBatch136140Evidence.Fingerprint(key));
        }
    }
}
