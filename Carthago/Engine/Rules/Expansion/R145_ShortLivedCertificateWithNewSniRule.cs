// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R145_ShortLivedCertificateWithNewSniRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R145_ShortLivedCertificateWithNewSniRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R145",
            Name: "Short-Lived Certificate With New SNI",
            Category: "TlsPki",
            Description: "Detects repeated external TLS sessions where a non-browser fingerprint reaches the same SNI using a very short-lived certificate.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R145.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R145",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls, RuleTelemetryKind.Ja3, RuleTelemetryKind.Ja4, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "tls_any", "tls_fingerprint_or_sni" },
            evidenceFields: new[] { "matched_conditions", "count", "tls.validityDays" },
            positiveConditions: new[]
            {
                "The record must contain TLS fingerprint, SNI, and certificate validity data.",
                "The destination must be external.",
                "The same fingerprint-to-SNI pair must repeat with a short-lived certificate within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert on browser-like TLS traffic.",
                "Do not alert on certificates with ordinary lifetimes."
            },
            minimumConfidence: 74,
            threshold: 3,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Custom enterprise agents and automated short-cert environments can look similar. Validate whether the client and SNI are approved."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive short lived cert repeated sni sample",
                "negative ninety day cert sample"
            });

        public R145_ShortLivedCertificateWithNewSniRule()
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
                || !IsShortLivedCertificate(record)
                || IsLikelyBrowserProcess(record.ProcessName))
            {
                return NoMatch();
            }

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 50);
            var count = CountWindowEvents($"{Rule.RuleId}:{fingerprint}:{host}", context.TimestampUtc, window);
            if (count < threshold)
                return NoMatch();

            var validityDays = CertificateValidityDays(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,short_lived_cert,repeated_fingerprint_to_sni", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("tls.validityDays", Math.Round(validityDays, 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-browser TLS fingerprint repeatedly reached the same external SNI with a very short-lived certificate.",
                "Severity is Medium because ephemeral certificates plus stable rare client fingerprints can indicate fast-rotating infrastructure or covert channels.",
                "Automated short-cert deployments can look similar. Validate whether the client and external SNI are part of an approved workflow.",
                "Review the certificate rotation cadence and the owning process for the fingerprint.",
                "Check whether the same fingerprint communicates with additional short-lived certificate hosts."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "Short-lived certificate repeatedly used with external SNI",
                "ShortLivedCertSni",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-fingerprint");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "short-lived-certificate");
                    confidence.AddEvidence(0.12, "threshold-reached");
                },
                count,
                window,
                $"{fingerprint}:{host}");
        }
    }
}
