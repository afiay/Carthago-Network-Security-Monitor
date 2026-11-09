// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R1355.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R818_IdeMarketplaceThenUnusualTlsPortRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R818",
            Name: "IDE marketplace TLS contact then different-peer TCP/8443 SYN",
            Category: "EvasionTunnel",
            Description: "IDE marketplace TLS contact then different-peer TCP/8443 SYN. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R818.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R818",
            Name = "IDE marketplace TLS contact then different-peer TCP/8443 SYN",
            Category = "EvasionTunnel",
            Description = "workbook.R1355: No IDE extension install, filesystem writes, active tunnel configuration or successful external connection is observed.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port", "tcp.flags" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Strict typed transport, coherent direction, unique packet IDs and the independent source predicate.",
                "Bounded instance-owned UTC correlation state; no live producer or replay quality claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reverse-time events and expired evidence fail closed.",
                "No inferred local file, identity, configuration, credential, success or compromise event."
            },
            FalsePositives = new[]
            {
                "Authorized administration, CI/CD, diagnostics, inventory and software upgrades may show these network patterns."
            },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R818_ide_marketplace_then_unusual_port_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();

        public R818_IdeMarketplaceThenUnusualTlsPortRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "code", "code.exe"))
                return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 443
                && string.Equals(r.Sni, "marketplace.visualstudio.com", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.TlsVersion))
            {
                _peers.Observe(key, r.Destination!, r.Id, context.TimestampUtc, true);
                return NoMatch();
            }
            if (!Research676Evidence.Syn(r) || r.DestinationPort != 8443
                || !_peers.Observe(key, r.Destination!, r.Id, context.TimestampUtc, false))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1355", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r818_ide_marketplace_then_unusual_port_syn", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "IDE marketplace TLS contact then different-peer TCP/8443 SYN observed; source attribution, authorization and outcome unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
