// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R138_SelfSignedCertificateToExternalHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R138_SelfSignedCertificateToExternalHostRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R138",
            Name: "Self-Signed Certificate To External Host",
            Category: "TlsPki",
            Description: "Detects TLS sessions to external hosts where the certificate subject and issuer indicate a self-signed certificate.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R138.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R138",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.certIssuer", "tls.certSubject" },
            positiveConditions: new[]
            {
                "The record must contain TLS certificate fields.",
                "The destination must be external.",
                "The certificate subject and issuer must indicate a self-signed certificate."
            },
            negativeConditions: new[]
            {
                "Do not alert on external TLS with no certificate identity fields.",
                "Do not alert when issuer and subject differ."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Security tooling, staging systems, and some privacy products can use self-signed certificates. Validate whether the external host is approved."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive self signed external tls sample",
                "negative externally trusted cert sample"
            });

        public R138_SelfSignedCertificateToExternalHostRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!IsTls(record) || !IsExternalAddress(host) || !IsLikelySelfSigned(record))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,self_signed_certificate", "rule"),
                new("tls.certIssuer", ShortText(record.CertIssuer ?? string.Empty), "tls"),
                new("tls.certSubject", ShortText(record.CertSubject ?? string.Empty), "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "A TLS session to an external host presented a self-signed certificate.",
                "Severity is Medium because self-signed certificates on external services often indicate staging infrastructure, interception, or non-standard control planes.",
                "Developer environments, privacy tooling, and sanctioned staging systems can look similar. Validate whether the destination and certificate are expected.",
                "Review the destination host ownership and whether the certificate identity is sanctioned.",
                "Inspect surrounding TLS destinations and process context for the same source."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "External TLS host presented self-signed certificate",
                "SelfSignedExternal",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "tls-context");
                    confidence.AddEvidence(0.22, "external-destination");
                    confidence.AddEvidence(0.22, "self-signed-certificate");
                },
                cooldownKey: $"{host}:{record.Source}");
        }
    }
}
