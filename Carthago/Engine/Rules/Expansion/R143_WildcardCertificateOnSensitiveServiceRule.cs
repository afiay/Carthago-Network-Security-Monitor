// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R143_WildcardCertificateOnSensitiveServiceRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R143_WildcardCertificateOnSensitiveServiceRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R143",
            Name: "Wildcard Certificate On Sensitive Service",
            Category: "TlsPki",
            Description: "Detects wildcard certificate subjects on sensitive non-web TLS service ports.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R143.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R143",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.certSubject", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain a TLS certificate subject.",
                "The certificate subject must be a wildcard.",
                "The service port must be a sensitive management, auth, or database port."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary HTTPS web ports.",
                "Do not alert on non-wildcard subjects."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Some appliances and managed platforms legitimately reuse wildcard certs across sensitive services. Validate whether the service is expected."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive wildcard cert on sensitive service sample",
                "negative wildcard cert on standard https sample"
            });

        public R143_WildcardCertificateOnSensitiveServiceRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || !NetworkBatch141145Evidence.CertificateSubject(record)
                || !IsSensitiveTlsService(record) || !IsWildcardSubject(record))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "observed_tls_tcp,sensitive_service_port,wildcard_subject", "rule"),
                new("tls.certSubject", "[REDACTED]", "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "A TLS/TCP session on a sensitive service port presented a wildcard certificate subject.",
                "Severity is Medium because wildcard name reuse on sensitive services may require identity-assurance review.",
                "Managed appliances often reuse wildcard certificates; this alone is not compromise.",
                "Confirm the service's expected certificate policy.",
                "Review SANs and the complete validated certificate chain."));

            return MatchTls(context, SeverityLevel.Medium,
                "Wildcard certificate observed on sensitive TLS service",
                "WildcardSensitiveService", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "tls-context");
                    confidence.AddEvidence(0.22, "sensitive-service-port");
                    confidence.AddEvidence(0.18, "wildcard-subject");
                }, cooldownKey: NetworkBatch136140Evidence.Fingerprint(
                    $"{record.Source}:{record.Destination}:{record.DestinationPort}:{record.CertSubject}"));
        }
    }
}
