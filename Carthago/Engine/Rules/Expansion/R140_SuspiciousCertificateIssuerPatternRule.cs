// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R140_SuspiciousCertificateIssuerPatternRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R140_SuspiciousCertificateIssuerPatternRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R140",
            Name: "Suspicious Certificate Issuer Pattern",
            Category: "TlsPki",
            Description: "Detects TLS certificates whose issuer string matches suspicious local, test, or interception patterns.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R140.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R140",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.certIssuer" },
            positiveConditions: new[]
            {
                "The record must contain a certificate issuer field.",
                "The issuer must match a suspicious local, test, or interception pattern."
            },
            negativeConditions: new[]
            {
                "Do not alert when issuer fields are absent.",
                "Do not alert on normal public CA issuer strings."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Local test infrastructure, interception proxies, and approved security tooling can present these issuer names."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive suspicious issuer sample",
                "negative public ca issuer sample"
            });

        public R140_SuspiciousCertificateIssuerPatternRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsTls(record) || !HasSuspiciousIssuer(record))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,suspicious_certificate_issuer", "rule"),
                new("tls.certIssuer", ShortText(record.CertIssuer ?? string.Empty), "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "The TLS certificate issuer matched a suspicious local, test, or interception-oriented pattern.",
                "Severity is Medium because unexpected issuer strings can indicate MITM tooling, ad hoc infrastructure, or poorly controlled certificates.",
                "Approved interception, QA, or staging systems can look similar. Validate whether the issuer is sanctioned in this environment.",
                "Identify whether the certificate issuer belongs to approved interception or test infrastructure.",
                "Review the same source and destination for additional TLS anomalies."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "Suspicious certificate issuer pattern observed",
                "SuspiciousIssuer",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "tls-context");
                    confidence.AddEvidence(0.24, "suspicious-issuer");
                },
                cooldownKey: $"{BestHost(record)}:{record.CertIssuer}");
        }
    }
}
