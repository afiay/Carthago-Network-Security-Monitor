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
            var sni = string.IsNullOrWhiteSpace(record.Sni) ? record.TlsSni : record.Sni;
            if (!IsTls(record) || !IsIpLiteralName(sni))
                return NoMatch();

            var normalized = BestHost(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,ip_literal_sni", "rule"),
                new("tls.sni", normalized, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "The TLS session explicitly used an IP literal as the SNI name.",
                "Severity is Medium because IP-literal TLS names can indicate evasive tooling, direct-to-host access, or poorly managed services.",
                "Legacy direct-IP management and diagnostics can look similar. Validate whether the client is expected to address the service by IP.",
                "Identify whether the destination is meant to be reached by hostname instead of raw IP.",
                "Review whether the same source uses normal SNI names for related destinations."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "IP literal used as TLS SNI",
                "IpLiteralSni",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "tls-context");
                    confidence.AddEvidence(0.24, "ip-literal-sni");
                },
                cooldownKey: $"{normalized}:{record.Source}");
        }
    }
}
