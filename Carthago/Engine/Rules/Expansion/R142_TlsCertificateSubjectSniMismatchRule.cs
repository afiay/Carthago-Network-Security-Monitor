// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R142_TlsCertificateSubjectSniMismatchRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R142_TlsCertificateSubjectSniMismatchRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R142",
            Name: "TLS Certificate Subject SNI Mismatch",
            Category: "TlsPki",
            Description: "Detects strong SNI-to-certificate-subject mismatches for external TLS sessions.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R142.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R142",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.sni", "tls.certSubject" },
            positiveConditions: new[]
            {
                "The record must contain both SNI and certificate subject fields.",
                "The destination must be external.",
                "The certificate subject must not plausibly cover the SNI."
            },
            negativeConditions: new[]
            {
                "Do not alert on wildcard coverage or exact name matches.",
                "Do not alert on same-root names that could be covered by SANs not exposed in the record."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Load balancers, intercepting proxies, or incomplete certificate enrichment can create apparent mismatches. Validate with full certificate context when possible."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive strong sni subject mismatch sample",
                "negative wildcard or same root sample"
            });

        public R142_TlsCertificateSubjectSniMismatchRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            var subject = CertificateSubjectName(record);
            if (!IsTls(record)
                || !IsExternalAddress(host)
                || string.IsNullOrWhiteSpace(subject)
                || !SubjectMismatchsSni(record))
            {
                return NoMatch();
            }

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,sni_subject_mismatch", "rule"),
                new("tls.sni", host, "tls"),
                new("tls.certSubject", subject, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "The external TLS SNI did not plausibly match the certificate subject.",
                "Severity is Medium because strong name mismatches can indicate interception, misconfiguration, or suspicious infrastructure.",
                "Load balancers, SAN-based certificates, and middleboxes can create apparent mismatches. Validate with the full certificate when possible.",
                "Review the complete certificate chain and SAN values if available.",
                "Check whether the destination is fronted by a proxy or CDN expected to present alternate names."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "External TLS session showed strong SNI/subject mismatch",
                "SniSubjectMismatch",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "tls-context");
                    confidence.AddEvidence(0.20, "external-destination");
                    confidence.AddEvidence(0.22, "sni-subject-mismatch");
                },
                cooldownKey: $"{host}:{subject}");
        }
    }
}
