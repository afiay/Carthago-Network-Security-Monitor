// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R1287.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R887_IdeProcessPublicTlsPeerPairRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R887", Name: "IDE-attributed TLS tunnel-name traffic to two public peers", Category: "CommandAndControl",
            Description: "An IDE process sends TLS/443 payloads to two distinct public IPs under the same tunnel-like SNI within 45s; installation, extension behavior and tunneling are not proved.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R887.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R887", Name = "IDE-attributed TLS tunnel-name traffic to two public peers", Category = "CommandAndControl",
            Description = "workbook.R1287: An IDE process sends TLS/443 payloads to two distinct public IPs under the same tunnel-like SNI within 45s; installation, extension behavior and tunneling are not proved.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "process.id", "tls.sni", "tls.version", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(45), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "ide_process_tls_tunnel_sni_two_public_peers",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R887_IdeProcessPublicTlsPeerPairRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "code.exe", "code", "idea64.exe", "idea64")
                || r.DestinationPort != 443 || r.L4Len is < 500 or > 1200
                || string.IsNullOrWhiteSpace(r.TlsVersion) || string.IsNullOrWhiteSpace(r.Sni)
                || r.Sni.Length > 253 || !r.Sni.Contains("tunnel", StringComparison.OrdinalIgnoreCase)
                || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId + "|" + r.Sni.ToLowerInvariant(),
                    r.Destination!, r.Id, context.TimestampUtc, 2, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1287", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "ide_process_tls_tunnel_sni_two_public_peers", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "IDE-attributed TLS tunnel-name traffic to two public peers; authentication, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_evidence");
                    confidence.AddEvidence(0.33, "owner_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_correlation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
