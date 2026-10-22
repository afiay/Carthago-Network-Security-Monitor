// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R147_EncryptedClienthelloOrEchIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R147_EncryptedClienthelloOrEchIndicatorRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R147",
            Name: "Encrypted ClientHello Or ECH Indicator",
            Category: "TlsPki",
            Description: "Detects explicit ECH or Encrypted ClientHello indicators only when real TLS context is present.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R147.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R147",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.alpn" },
            positiveConditions: new[]
            {
                "The record must contain TLS context.",
                "The record text must explicitly indicate ECH or Encrypted ClientHello."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only ECH mentions without TLS evidence.",
                "Do not alert on ordinary TLS traffic that lacks ECH indicators."
            },
            minimumConfidence: 60,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Modern browsers and privacy features can legitimately use ECH. Treat as context, not inherently malicious."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive explicit ech indicator sample",
                "negative ordinary tls sample"
            });

        public R147_EncryptedClienthelloOrEchIndicatorRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsTls(record) || !ContainsAny(Text(record), "encrypted client hello", "encrypted_client_hello", " ech "))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,ech_indicator", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "The TLS telemetry explicitly indicated ECH or Encrypted ClientHello usage.",
                "Severity is Low because ECH is a modern privacy signal that is useful for context but not inherently malicious.",
                "Modern browsers and privacy-preserving services can legitimately use ECH. Treat this as context unless correlated with other suspicious signals.",
                "Review whether the source process and destination are expected to use privacy-enhancing TLS features.",
                "Correlate with other suspicious destinations or fingerprints before escalating."));

            return MatchTls(
                context,
                SeverityLevel.Low,
                "ECH or Encrypted ClientHello indicator observed",
                "EchIndicator",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "tls-context");
                    confidence.AddEvidence(0.12, "ech-indicator");
                },
                cooldownKey: $"{BestHost(record)}:{record.Source}");
        }
    }
}
