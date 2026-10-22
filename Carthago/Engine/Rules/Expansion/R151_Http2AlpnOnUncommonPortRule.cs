// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R151_Http2AlpnOnUncommonPortRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R151_Http2AlpnOnUncommonPortRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R151",
            Name: "HTTP2 ALPN On Uncommon Port",
            Category: "TlsPki",
            Description: "Detects non-browser external TLS sessions that negotiate HTTP/2 ALPN on uncommon ports.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R151.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R151",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.alpn", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The record must contain TLS ALPN context.",
                "The ALPN must indicate HTTP/2.",
                "The destination port must be an uncommon HTTP/2 TLS port and the traffic should not be ordinary browser use."
            },
            negativeConditions: new[]
            {
                "Do not alert on browser-like traffic.",
                "Do not alert on ordinary HTTPS ports or non-h2 ALPN."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Custom APIs and reverse proxies can legitimately use HTTP/2 on uncommon ports. Validate whether the service and process are approved."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive non browser h2 uncommon port sample",
                "negative browser h2 uncommon port sample"
            });

        public R151_Http2AlpnOnUncommonPortRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!IsTls(record)
                || !HasH2Alpn(record)
                || !IsUncommonH2Port(record)
                || !IsExternalAddress(host)
                || IsLikelyBrowserProcess(record.ProcessName))
            {
                return NoMatch();
            }

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "tls_context,external_destination,h2_alpn,uncommon_port", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A non-browser external TLS session negotiated HTTP/2 ALPN on an uncommon port.",
                "Severity is Medium because HTTP/2 on unusual ports can indicate custom APIs, covert channels, or niche infrastructure.",
                "Custom APIs and reverse proxies can legitimately use HTTP/2 on uncommon ports. Validate whether the destination and process are approved.",
                "Review the process, port, and destination service ownership.",
                "Check whether the same client uses the same ALPN on standard HTTPS services."));

            return MatchTls(
                context,
                SeverityLevel.Medium,
                "HTTP/2 ALPN negotiated on uncommon TLS port",
                "H2UncommonPort",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-context");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "h2-on-uncommon-port");
                },
                cooldownKey: $"{host}:{record.DestinationPort}:{record.Alpn}");
        }
    }
}
