// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1717.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R899_VmwarePublicResolverTlsSniRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R899", Name: "VMware management-process TLS to public resolver SNI", Category: "DnsAdvanced",
            Description: "Local hostd/vpxa attribution and TLS/443 to a public IP with exact recognized resolver SNI; HTTPS DNS requests, resolver identity, VMware asset role and tunneling are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R899.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R899", Name = "VMware management-process TLS to public resolver SNI", Category = "DnsAdvanced",
            Description = "workbook.R1717: Local hostd/vpxa attribution and TLS/443 to a public IP with exact recognized resolver SNI; HTTPS DNS requests, resolver identity, VMware asset role and tunneling are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "process.id", "process.name", "tls.sni", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and source-specific local process association.", "Bounded UTC evidence where correlation is required." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong process or direction, duplicates or stale evidence fail closed.",
                "No unobserved endpoint execution, authorization, authentication, decrypted contents or security outcome asserted." },
            FalsePositives = new[] { "Approved administration, software deployment, diagnostics and routine infrastructure activity can match." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "vmware_management_public_resolver_sni_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        
        public R899_VmwarePublicResolverTlsSniRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "hostd", "hostd.exe", "vpxa", "vpxa.exe")
                || r.DestinationPort != 443 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse) return NoMatch();
            var sni = r.Sni.TrimEnd('.').ToLowerInvariant();
            if (sni is not ("dns.google" or "cloudflare-dns.com" or "dns.quad9.net")) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1717", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "vmware_management_public_resolver_sni_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "VMware management-process TLS to public resolver SNI observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
