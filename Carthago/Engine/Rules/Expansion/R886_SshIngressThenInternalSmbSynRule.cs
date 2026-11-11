// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R1513.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R886_SshIngressThenInternalSmbSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R886", Name: "Public SSH SYN followed by private SMB SYN", Category: "LateralMovement",
            Description: "Public SSH SYN into a private host followed by that host initiating private SMB/445 SYN within 60s; no SSH login, interactive shell, privilege escalation or lateral success is proved.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R886.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R886", Name = "Public SSH SYN followed by private SMB SYN", Category = "LateralMovement",
            Description = "workbook.R1513: Public SSH SYN into a private host followed by that host initiating private SMB/445 SYN within 60s; no SSH login, interactive shell, privilege escalation or lateral success is proved.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "destination.port", "tcp.flags", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_ssh_syn_then_same_private_host_internal_smb_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R886_SshIngressThenInternalSmbSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r)) return NoMatch();
            var first = Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 22;
            var second = Research786NetworkEvidence.Internal(r) && r.DestinationPort == 445
                && !string.Equals(r.Source, r.Destination, StringComparison.Ordinal);
            if (!first && !second) return NoMatch();
            var host = first ? r.Destination! : r.Source!;
            if (!_stages.Observe(host, r.Id, context.TimestampUtc, first, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1513", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_ssh_syn_then_same_private_host_internal_smb_syn", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public SSH SYN followed by private SMB SYN; authentication, causality and outcome remain unverified.",
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
