// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R149_IpLiteralUsedAsTlsNameRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R149_IpLiteralUsedAsTlsNameRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R149",
            Name: "IP Literal Used As TLS Name",
            Category: "TlsPki",
            Description: "Detects TLS sessions that explicitly use an IP literal as the SNI name.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R149.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R149",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.sni" },
            positiveConditions: new[]
            {
                "The record must contain SNI context.",
                "The SNI or TLS name must parse as an IP literal."
            },
            negativeConditions: new[]
            {
                "Do not alert when SNI is absent.",
                "Do not alert when the TLS name is a normal hostname."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Direct-IP management, diagnostics, and some legacy clients can legitimately use IP literals in TLS."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive ip literal sni sample",
                "negative hostname sni sample"
            });

        public R149_IpLiteralUsedAsTlsNameRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var sni = string.IsNullOrWhiteSpace(record.TlsSni) ? record.Sni : record.TlsSni;
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || string.IsNullOrWhiteSpace(sni)
                || !string.IsNullOrWhiteSpace(record.Sni) && !string.IsNullOrWhiteSpace(record.TlsSni)
                    && !string.Equals(record.Sni.Trim(), record.TlsSni.Trim(), StringComparison.OrdinalIgnoreCase)
                || !IsIpLiteralName(sni))
                return NoMatch();

            var normalized = sni.Trim();
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "attributed_tls_tcp,explicit_ip_literal_sni", "rule"),
                new("tls.sni", normalized, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "The TLS parser reported an IP literal in SNI rather than a normal hostname.",
                "Severity is Medium because direct-IP TLS naming may merit configuration review.",
                "Diagnostics and legacy clients may legitimately use IP names in TLS.",
                "Confirm the destination IP is expected and certificate name validation is appropriate.",
                "Correlate with sanctioned direct-IP management."));
            return MatchTls(context, SeverityLevel.Medium, "IP literal observed as TLS SNI",
                "IpLiteralSni", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "tls-context");
                    confidence.AddEvidence(0.24, "ip-literal-sni");
                }, cooldownKey: NetworkBatch136140Evidence.Fingerprint($"{record.Source}:{normalized}"));
        }
    }
}
