// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R1208.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R892_BroadcastUdpNineThenRdpSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R892", Name: "Private broadcast UDP/9 then RDP SYN from same source", Category: "LateralMovement",
            Description: "Private source sends broadcast-address UDP/9 payload sized 102 bytes then SYNs to a private RDP/3389 peer within 45s; magic-packet bytes, host wake, firewall change and successful RDP are not decoded.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R892.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R892", Name = "Private broadcast UDP/9 then RDP SYN from same source", Category = "LateralMovement",
            Description = "workbook.R1208: Private source sends broadcast-address UDP/9 payload sized 102 bytes then SYNs to a private RDP/3389 peer within 45s; magic-packet bytes, host wake, firewall change and successful RDP are not decoded.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "protocol", "destination.port", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(45), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_broadcast_udp9_then_private_rdp_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R892_BroadcastUdpNineThenRdpSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.UdpData(r)
                && Research786NetworkEvidence.Internal(r) && r.DestinationPort == 9
                && r.L4Len == 102 && r.Destination!.EndsWith(".255", StringComparison.Ordinal)
                && Research786NetworkEvidence.Subnet24(r.Source!) == Research786NetworkEvidence.Subnet24(r.Destination!)
                && r.HttpMethod == null && r.DnsQname == null && r.TlsVersion == null;
            var second = Research676Evidence.Syn(r) && Research786NetworkEvidence.Internal(r)
                && r.DestinationPort == 3389;
            if (!first && !second) return NoMatch();
            if (!_stages.Observe(r.Source!, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1208", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "private_broadcast_udp9_then_private_rdp_syn", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Private broadcast UDP/9 then RDP SYN from same source; authentication, causality and outcome remain unverified.",
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
