// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R2069.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R835_MshtaFetchThenRundll32TlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R835", Name: "mshta HTA GET then rundll32 other-peer TLS payload", Category: "CommandControl",
            Description: "Same local IP two-process network sequence only; no payload execution, process ancestry, C2 command, or multi-stage implant inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R835.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R835", Name = "mshta HTA GET then rundll32 other-peer TLS payload", Category = "CommandControl",
            Description = "workbook.R2069: Same local IP two-process network sequence only; no payload execution, process ancestry, C2 command, or multi-stage implant inferred.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id" },
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
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "mshta_hta_get_then_rundll32_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();
        public R835_MshtaFetchThenRundll32TlsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r))
                return NoMatch();
            if (r.DestinationPort == 80 && Research676Evidence.Process(r, "mshta.exe")
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "GET" && uri.EndsWith(".hta", StringComparison.OrdinalIgnoreCase))
            {
                _peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (r.DestinationPort != 8443 || !Research676Evidence.Process(r, "rundll32.exe")
                || r.L4Len is < 256 or > 4096 || string.IsNullOrWhiteSpace(r.TlsVersion)
                || string.IsNullOrWhiteSpace(r.Sni) || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse
                || string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !_peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2069", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "mshta_hta_get_then_rundll32_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "mshta HTA GET then rundll32 other-peer TLS payload observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        
    }
}

