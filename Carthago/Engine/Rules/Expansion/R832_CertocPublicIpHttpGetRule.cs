// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R3083.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R832_CertocPublicIpHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R832", Name: "CertOC process GET to a direct public IP HTTP origin", Category: "IdentityAccess",
            Description: "CertOC-associated direct-IP cleartext HTTP GET only; command-line GetCACAPS, CA response, material write and certificate trust are not visible.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R832.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R832", Name = "CertOC process GET to a direct public IP HTTP origin", Category = "IdentityAccess",
            Description = "workbook.R3083: CertOC-associated direct-IP cleartext HTTP GET only; command-line GetCACAPS, CA response, material write and certificate trust are not visible.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 packets, exact source-specific predicate and bounded UTC correlation where used.",
                "Packet ID/protocol/process association is observation-only; no authenticated endpoint action asserted."
            },
            NegativeConditions = new[]
            {
                "Missing/contradictory fields, duplicate packet IDs, reversed UTC order and stale state fail closed.",
                "Do not infer completed transfers, successful access, exploit execution, credentials or actor identity."
            },
            FalsePositives = new[]
            {
                "Authorized updates, administrative troubleshooting, diagnostics, scans and red-team activity can match; apply asset/process allowlists before promotion."
            },
            MinimumConfidence = 80, WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "certoc_direct_public_ip_get",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        
        public R832_CertocPublicIpHttpGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort != 80 || !Research676Evidence.Process(r, "certoc.exe")
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || uri.Length < 3 || !DirectIpHost(r))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R3083", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "certoc_direct_public_ip_get", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "CertOC process GET to a direct public IP HTTP origin observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        private static bool DirectIpHost(TrafficRecord r)
            => !string.IsNullOrWhiteSpace(r.HttpHost)
                && System.Net.IPAddress.TryParse(r.HttpHost, out var host)
                && host.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && string.Equals(host.ToString(), r.Destination, StringComparison.Ordinal);
    }
}

