// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R139_WeakTlsVersionObservedRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R139_WeakTlsVersionObservedRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R139",
            Name: "Weak TLS Version Observed",
            Category: "TlsPki",
            Description: "Detects actual TLS 1.0, TLS 1.1, or SSLv3 usage from parsed TLS version metadata.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R139.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R139",
            maturity: RulePrecisionMaturity.Core,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.version" },
            positiveConditions: new[]
            {
                "The record must contain a parsed TLS version.",
                "The version must be TLS 1.0, TLS 1.1, or SSLv3."
            },
            negativeConditions: new[]
            {
                "Do not alert on TLS 1.2, TLS 1.3, or absent TLS version fields.",
                "Do not alert from AnyText-only protocol mentions."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(5),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Legacy appliances and sanctioned compatibility endpoints can still negotiate weak TLS. Validate whether the downgrade is expected and approved."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive weak tls version sample",
                "negative modern tls version sample"
            });

        public R139_WeakTlsVersionObservedRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch136140Evidence.TlsSession(record)
                || !NetworkBatch136140Evidence.WeakVersion(record.TlsVersion, out var version))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,weak_tls_version", "rule"),
                new("tls.version", version, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "The TLS session negotiated a weak legacy protocol version.",
                "Severity is High because TLS 1.0, TLS 1.1, and SSLv3 materially weaken transport security and are often prohibited by policy.",
                "Legacy compatibility endpoints can still negotiate weak TLS. Validate whether the service is an approved exception.",
                "Identify the server and client responsible for the weak handshake.",
                "Confirm whether stronger TLS versions are supported but not negotiated."));

            return MatchTls(
                context,
                SeverityLevel.High,
                "Weak TLS version negotiated",
                "WeakTlsVersion",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.42, "tls-context");
                    confidence.AddEvidence(0.32, "weak-version");
                },
                cooldownKey: $"{BestHost(record)}:{version}");
        }
    }
}
