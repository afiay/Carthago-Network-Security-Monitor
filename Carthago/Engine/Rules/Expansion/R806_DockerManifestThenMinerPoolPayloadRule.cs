// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored, 0 tests executed; workbook.R1175.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R806_DockerManifestThenMinerPoolPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R806",
            Name: "Docker registry manifest GET then xmrig pool-service payload",
            Category: "Execution",
            Description: "Docker manifest HTTP GET followed by same-host xmrig public TCP/3333 payload. No container creation, launch or compromise inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R806.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R806",
            Name = "Docker registry manifest GET then xmrig pool-service payload",
            Category = "Execution",
            Description = "workbook.R1175: Docker-process manifest fetch then xmrig-process egress are network observations only; no container creation, CPU utilization or privilege claim.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            // The HTTP and TCP/3333 stages must pass the packet selector separately.
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Typed and mutually coherent transport/direction fields plus the narrow independent predicate.",
                "Bounded instance-owned monotonic UTC state and distinct packet provenance; not live validation."
            },
            NegativeConditions = new[]
            {
                "Incomplete/contradictory process, protocol, port, peer or context, duplicate IDs and stale time fail closed.",
                "No free-form Info assertion, secret, raw payload, endpoint audit, authorization or success claim."
            },
            FalsePositives = new[]
            {
                "Approved operations, maintenance, diagnostics and scripted administration can produce similar traffic."
            },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R806_docker_manifest_then_miner_other_peer",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive/benign", "missing/contradictory telemetry", "duplicate/reverse/expiry",
                "cooldown recovery", "privacy", "Candidate Shadow", "independence/registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();

        public R806_DockerManifestThenMinerPoolPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r))
                return NoMatch();
            if (r.DestinationPort == 80 && Research676Evidence.Process(r, "docker", "docker.exe")
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "GET" && uri.StartsWith("/v2/", StringComparison.OrdinalIgnoreCase)
                && uri.Contains("/manifests/", StringComparison.OrdinalIgnoreCase))
            {
                _peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (!Research676Evidence.Process(r, "xmrig", "xmrig.exe")
                || r.DestinationPort != 3333 || r.L4Len is < 256 or > 4096
                || r.HttpMethod != null || r.DnsQname != null || r.TlsVersion != null
                || !_peers.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var observation = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1175", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r806_docker_manifest_then_miner_other_peer", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_impact_causality_and_authorization_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Docker manifest GET then xmrig pool-port egress observed; container creation, permission and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_local_process_evidence");
                    confidence.AddEvidence(0.33, "independent_workbook_sourced_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_packet_correlation");
                },
                count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
