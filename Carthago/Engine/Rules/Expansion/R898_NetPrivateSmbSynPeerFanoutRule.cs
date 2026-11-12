// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1896.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R898_NetPrivateSmbSynPeerFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R898", Name: "Net-attributed private SMB SYN peer fanout", Category: "Discovery",
            Description: "Same private source and net/net1 PID SYNs to three distinct private TCP/445 peers in 45 seconds; share enumeration, SMB authentication and lateral success are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R898.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R898", Name = "Net-attributed private SMB SYN peer fanout", Category = "Discovery",
            Description = "workbook.R1896: Same private source and net/net1 PID SYNs to three distinct private TCP/445 peers in 45 seconds; share enumeration, SMB authentication and lateral success are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "packet.id", "process.id", "process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and source-specific local process association.", "Bounded UTC evidence where correlation is required." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong process or direction, duplicates or stale evidence fail closed.",
                "No unobserved endpoint execution, authorization, authentication, decrypted contents or security outcome asserted." },
            FalsePositives = new[] { "Approved administration, software deployment, diagnostics and routine infrastructure activity can match." },
            MinimumConfidence = 80, WindowThreshold = 3, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "net_private_smb_syn_three_peers",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R898_NetPrivateSmbSynPeerFanoutRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.Internal(r)
                || !Research676Evidence.Syn(r) || !Research676Evidence.Process(r, "net.exe", "net", "net1.exe", "net1")
                || r.DestinationPort != 445 || string.Equals(r.Source, r.Destination, StringComparison.Ordinal)
                || r.Sni != null || r.HttpUri != null || r.DnsIsResponse) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (!_distinct.Observe(key, r.Destination!, r.Id, context.TimestampUtc, 3, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1896", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "net_private_smb_syn_three_peers", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Net-attributed private SMB SYN peer fanout observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 3, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
