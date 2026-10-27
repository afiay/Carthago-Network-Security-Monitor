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

        private readonly NetworkBatch141145Window _observations = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = NetworkBatch141145Evidence.Sni(record);
            var fingerprint = NetworkBatch141145Evidence.Fingerprint(record);
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || host == null || fingerprint == null
                || !NetworkBatch136140Evidence.ExternalDestination(record)
                || !NetworkBatch141145Evidence.CertificateLifetime(record, out var validityDays)
                || validityDays > 30
                || IsLikelyBrowserProcess(record.ProcessName))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 900, 60, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 50);
            // Do not combine different certificate lifetimes into one apparent repetition.
            var key = $"{record.Source}:{fingerprint}:{host}:{record.CertValidFrom:O}:{record.CertValidTo:O}";
            if (!_observations.Observe(key, record.Id, context.TimestampUtc, window, out var count)
                || count < threshold)
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "observed_tls_tcp,external_socket,short_certificate,distinct_repeated_fingerprint_sni", "rule"),
                new("count", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("tls.validityDays", Math.Round(validityDays, 1).ToString(System.Globalization.CultureInfo.InvariantCulture), "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "One client repeatedly presented the same fingerprint/SNI pair with the same short certificate validity interval.",
                "Severity is Medium: this pattern warrants review, but neither new SNI nor a suspicious certificate issuer is independently established.",
                "Short-lived certificates are common in automated authorized environments.",
                "Verify process ownership, certificate identity and approved short-certificate automation.",
                "Correlate with historical first-seen telemetry before classifying as new infrastructure."));

            return MatchTls(context, SeverityLevel.Medium,
                "Short-lived certificate repeatedly observed with external SNI",
                "ShortLivedCertSni", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-fingerprint");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "short-lived-certificate");
                    confidence.AddEvidence(0.12, "threshold-reached");
                }, count, window, NetworkBatch136140Evidence.Fingerprint(key));
        }
    }
}
