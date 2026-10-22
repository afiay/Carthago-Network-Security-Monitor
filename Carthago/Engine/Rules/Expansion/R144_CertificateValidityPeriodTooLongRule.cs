// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R144_CertificateValidityPeriodTooLongRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R144_CertificateValidityPeriodTooLongRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R144",
            Name: "Certificate Validity Period Too Long",
            Category: "TlsPki",
            Description: "Detects external TLS certificates whose validity period is unusually long.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R144.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R144",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.validityDays" },
            positiveConditions: new[]
            {
                "The record must contain certificate validity dates.",
                "The destination must be external.",
                "The certificate validity period must be unusually long."
            },
            negativeConditions: new[]
            {
                "Do not alert on missing certificate dates.",
                "Do not alert on modern short-lived or standard-lived certificates."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Legacy public infrastructure and some enterprise PKI deployments can still use longer-lived certificates."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive long validity cert sample",
                "negative standard validity cert sample"
            });

        public R144_CertificateValidityPeriodTooLongRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var validityDays = CertificateValidityDays(record);
            if (!IsTls(record) || !IsExternalAddress(host) || !IsValidityTooLong(record))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,long_validity_certificate", "rule"),
                new("tls.validityDays", Math.Round(validityDays).ToString(System.Globalization.CultureInfo.InvariantCulture), "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "An external TLS certificate had an unusually long validity period.",
                "Severity is Medium because very long-lived certificates can weaken revocation and key-rotation hygiene.",
                "Legacy public services and some enterprise PKI models still use longer cert lifetimes. Validate whether the duration is an approved exception.",
                "Identify the certificate owner and whether the long validity period is expected.",
                "Review the same host for additional certificate hygiene issues such as issuer anomalies or subject mismatches."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "External TLS certificate validity period unusually long",
                "LongValidityCertificate",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "tls-context");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.20, "long-validity");
                },
                cooldownKey: $"{host}:{Math.Round(validityDays)}");
        }
    }
}
