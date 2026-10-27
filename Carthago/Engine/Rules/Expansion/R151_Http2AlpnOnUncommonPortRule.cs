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
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || !string.Equals(record.Alpn?.Trim(), "h2", StringComparison.OrdinalIgnoreCase)
                || !IsUncommonH2Port(record)
                || !NetworkBatch136140Evidence.ExternalDestination(record)
                || IsLikelyBrowserProcess(record.ProcessName))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "attributed_tls_tcp,observed_h2_alpn,external_socket,uncommon_port", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "TLS telemetry explicitly reported h2 ALPN on an uncommon external service port.",
                "Severity is Medium: unusual ALPN/port combinations can indicate customized applications, not necessarily misuse.",
                "Proxies and enterprise APIs commonly negotiate h2 on nonstandard ports.",
                "Check the server's approved listening port and client ownership.",
                "Verify whether ALPN reflects negotiation rather than advertised offerings."));
            return MatchTls(context, SeverityLevel.Medium, "HTTP/2 ALPN observed on uncommon TLS port",
                "H2UncommonPort", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-context");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "h2-on-uncommon-port");
                }, cooldownKey: NetworkBatch136140Evidence.Fingerprint(
                    $"{record.Source}:{record.Destination}:{record.DestinationPort}:h2"));
        }
    }
}
