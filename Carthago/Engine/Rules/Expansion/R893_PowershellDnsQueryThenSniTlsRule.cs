// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R2704.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R893_PowershellDnsQueryThenSniTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R893", Name: "PowerShell-attributed DNS A query then matching SNI TLS", Category: "CommandAndControl",
            Description: "A PowerShell-attributed private DNS A query precedes TLS/443 from the same private source and process to a public peer with matching SNI within 60s; DNS response, asset role, allowlist and C2 are not proved.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R893.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R893", Name = "PowerShell-attributed DNS A query then matching SNI TLS", Category = "CommandAndControl",
            Description = "workbook.R2704: A PowerShell-attributed private DNS A query precedes TLS/443 from the same private source and process to a public peer with matching SNI within 60s; DNS response, asset role, allowlist and C2 are not proved.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Dns, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "process.id", "dns.qname", "tls.sni", "source", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "powershell_dns_a_query_then_same_domain_public_sni_tls",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R893_PowershellDnsQueryThenSniTlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)
                || !Research676Evidence.Process(r, "powershell", "powershell.exe", "pwsh", "pwsh.exe"))
                return NoMatch();
            var first = Research786NetworkEvidence.DnsQuestion(r)
                && Research786NetworkEvidence.Internal(r)
                && string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase);
            var second = Research786NetworkEvidence.TcpData(r)
                && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 443
                && r.L4Len is >= 500 and <= 1200 && !string.IsNullOrWhiteSpace(r.TlsVersion)
                && !string.IsNullOrWhiteSpace(r.Sni) && r.HttpMethod == null && r.HttpUri == null
                && r.DnsQname == null;
            if (!first && !second) return NoMatch();
            var name = first ? r.DnsQname : r.Sni;
            if (string.IsNullOrWhiteSpace(name) || name.Length > 253) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId + "|" + name.TrimEnd('.').ToLowerInvariant();
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2704", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "powershell_dns_a_query_then_same_domain_public_sni_tls", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "PowerShell-attributed DNS A query then matching SNI TLS; authentication, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_evidence");
                    confidence.AddEvidence(0.33, "owner_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_correlation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
