// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R1649.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R889_HostdVpxaTlsCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R889", Name: "ESXi management TLS/8443 repeated payload cadence", Category: "CommandAndControl",
            Description: "Four near-sized hostd/vpxa-attributed TLS/8443 data packets to one public peer spaced 5–20 seconds apart within 65s; neither junk payload encoding nor C2 is decoded.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R889.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R889", Name = "ESXi management TLS/8443 repeated payload cadence", Category = "CommandAndControl",
            Description = "workbook.R1649: Four near-sized hostd/vpxa-attributed TLS/8443 data packets to one public peer spaced 5–20 seconds apart within 65s; neither junk payload encoding nor C2 is decoded.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "process.id", "tls.sni", "tls.version", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(65), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "esxi_management_tls8443_four_packet_cadence",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CadenceWindow _cadence = new();
        public R889_HostdVpxaTlsCadenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "hostd", "hostd.exe", "vpxa", "vpxa.exe")
                || r.DestinationPort != 8443 || r.L4Len is not int payloadLength || payloadLength is < 600 or > 900
                || string.IsNullOrWhiteSpace(r.TlsVersion) || string.IsNullOrWhiteSpace(r.Sni)
                || r.Sni.Length > 253 || r.HttpMethod != null || r.HttpUri != null || r.DnsQname != null
                || !_cadence.Observe(r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + r.Sni.ToLowerInvariant(),
                    r.Id, payloadLength, context.TimestampUtc, 4, 5, 20, 32, 65)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1649", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "esxi_management_tls8443_four_packet_cadence", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "ESXi management TLS/8443 repeated payload cadence; authentication, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_evidence");
                    confidence.AddEvidence(0.33, "owner_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_correlation");
                }, count: 4, windowSeconds: 65);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
