// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R265_PublicVpnProxyDomainContactRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R265_PublicVpnProxyDomainContactRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R265",
            Name: "Public VPN Proxy Domain Contact",
            Category: "EvasionInfra",
            Description: "Detects public vpn proxy domain contact only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R265.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R265",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 75,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "User privacy tools, travel VPNs, browser extensions, and sanctioned testing may contact these services." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R265 evidence-gated sample", "negative R265 descriptor-only sample", "negative R265 missing telemetry sample" });

        public R265_PublicVpnProxyDomainContactRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch261265Evidence.ProviderTls(r, out var provider)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_tls_sni,exact_provider_domain_suffix", "rule"),
                new("provider.category", provider, "rule")
            };
            evidence.AddRange(AnalystContext("TLS SNI names a known public VPN provider on an external TCP connection.",
                "SNI contact does not prove VPN tunnel establishment or use of a proxy.",
                "Provider websites, support pages and security research can produce benign TLS SNI.",
                "Corroborate with process identity and approved VPN policy before escalation."));
            return MatchEvasionInfra(context, SeverityLevel.Medium, "Public VPN provider TLS SNI observed (tunnel unverified)",
                "PublicVpnProxy", evidence, c => { c.AddEvidence(0.34, "typed-tls-sni"); c.AddEvidence(0.22, "exact-domain"); c.AddEvidence(0.18, "external-tcp"); },
                cooldownKey: r.Source + "|" + r.Destination + "|" + provider);
        }
    }
}
