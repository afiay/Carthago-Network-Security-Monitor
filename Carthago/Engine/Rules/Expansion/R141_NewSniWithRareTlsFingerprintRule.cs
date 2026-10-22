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

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var fingerprint = string.IsNullOrWhiteSpace(record.Ja4) ? record.Ja3 : record.Ja4;
            if (!IsTls(record)
                || string.IsNullOrWhiteSpace(host)
                || string.IsNullOrWhiteSpace(fingerprint)
                || !IsExternalAddress(host)
                || IsLikelyBrowserProcess(record.ProcessName))
            {
                return NoMatch();
            }

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 50);
            var count = CountWindowEvents($"{Rule.RuleId}:{fingerprint}:{host}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,repeated_fingerprint_to_sni", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("tls.sni", host, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-browser TLS fingerprint repeatedly connected to the same external SNI within a short window.",
                "Severity is Medium because stable uncommon fingerprints against targeted SNIs can indicate bespoke tooling or malware C2 staging.",
                "Custom enterprise agents and niche SaaS clients can look similar. Validate whether the process and destination are approved.",
                "Review the process, user, and host lineage for the fingerprinted client.",
                "Check whether the same fingerprint appears against other unusual destinations."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "Repeated rare TLS fingerprint observed against external SNI",
                "RareFingerprintSni",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "tls-fingerprint");
                    confidence.AddEvidence(0.20, "external-destination");
                    confidence.AddEvidence(0.18, "threshold-reached");
                },
                count,
                window,
                $"{fingerprint}:{host}");
        }
    }
}
