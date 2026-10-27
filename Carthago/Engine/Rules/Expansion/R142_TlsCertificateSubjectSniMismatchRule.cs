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
            var host = NetworkBatch141145Evidence.Sni(record);
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || host == null || !NetworkBatch136140Evidence.ExternalDestination(record)
                || !NetworkBatch141145Evidence.CertificateSubject(record)
                || !SubjectMismatchsSni(record))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "observed_tls_tcp,external_socket,sni_subject_root_mismatch", "rule"),
                new("tls.sni", host, "tls"),
                new("tls.certSubject", "[REDACTED]", "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "Observed TLS SNI and a supplied certificate subject belong to different apparent domain roots.",
                "Severity is Medium: a mismatch may indicate interception or configuration drift, but absent SAN fields prevent certificate name validation.",
                "SAN-covered certificates, proxies and intercepting devices can appear mismatched. Review actual SAN coverage.",
                "Obtain the complete certificate and handshake attribution before escalating.",
                "Check whether enterprise TLS interception or CDN routing is approved."));

            return MatchTls(context, SeverityLevel.Medium,
                "External TLS session showed apparent SNI/subject mismatch",
                "SniSubjectMismatch", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "tls-context");
                    confidence.AddEvidence(0.20, "external-destination");
                    confidence.AddEvidence(0.22, "sni-subject-mismatch");
                }, cooldownKey: NetworkBatch136140Evidence.Fingerprint(
                    $"{record.Source}:{host}:{record.CertSubject}"));
        }
    }
}
