// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R148_TlsToDynamicDnsHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R148_TlsToDynamicDnsHostRule : TlsPkiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R148",
            Name: "TLS To Dynamic DNS Host",
            Category: "TlsPki",
            Description: "Detects external TLS sessions to hosted subdomains on dynamic-DNS providers, while suppressing provider root sites and browser noise.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R148.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateTlsPkiProfile(
            ruleId: "R148",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Tls },
            requiredFields: new[] { "source", "destination_or_host", "tls_any" },
            evidenceFields: new[] { "matched_conditions", "tls.sni" },
            positiveConditions: new[]
            {
                "The record must contain TLS host context.",
                "The destination must be external.",
                "The TLS host must be a hosted subdomain on a known dynamic-DNS provider."
            },
            negativeConditions: new[]
            {
                "Do not alert on provider root domains or documentation sites.",
                "Do not alert on browser-like traffic by default."
            },
            minimumConfidence: 70,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host",
            falsePositives: new[]
            {
                "Home-lab, remote-access, and sanctioned tunnel tooling can use dynamic-DNS providers. Validate whether the subdomain is approved."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive tls dynamic dns subdomain sample",
                "negative provider root or browser sample"
            });

        public R148_TlsToDynamicDnsHostRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = NetworkBatch141145Evidence.Sni(record);
            if (!NetworkBatch141145Evidence.TlsSession(context)
                || host == null
                || !NetworkBatch136140Evidence.ExternalDestination(record)
                || !HostUsesDynamicDnsProvider(host)
                || IsLikelyBrowserProcess(record.ProcessName))
                return NoMatch();

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "attributed_tls_tcp,external_socket,dynamic_dns_sni", "rule"),
                new("tls.sni", host, "tls")
            };
            evidenceItems.AddRange(AnalystContext(
                "Observed TLS SNI is a hosted dynamic DNS provider subdomain on an external socket.",
                "Severity is Medium because transient externally hosted endpoints may merit review.",
                "Approved homelab, remote support and development tools frequently use dynamic DNS.",
                "Confirm ownership and approval of the specific subdomain.",
                "Correlate with process lineage before escalating."));
            return MatchTls(context, SeverityLevel.Medium,
                "TLS session to dynamic-DNS hosted SNI", "DynamicDnsTls", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "tls-context");
                    confidence.AddEvidence(0.18, "external-destination");
                    confidence.AddEvidence(0.18, "dynamic-dns-subdomain");
                }, cooldownKey: NetworkBatch136140Evidence.Fingerprint($"{record.Source}:{host}"));
        }
    }
}
