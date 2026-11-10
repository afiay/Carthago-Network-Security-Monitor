// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2865.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R856_FrpcPublicTcp7000SynThenPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R856", Name: "Frpc public TCP/7000 SYN then payload", Category: "CommandAndControl",
            Description: "A frpc-attributed public TCP/7000 SYN precedes same-peer payload within 30s; CLI options, relay use and connection success unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R856.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R856", Name = "Frpc public TCP/7000 SYN then payload", Category = "CommandAndControl",
            Description = "workbook.R2865: A frpc-attributed public TCP/7000 SYN precedes same-peer payload within 30s; CLI options, relay use and connection success unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(30), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "frpc_public_7000_syn_then_payload", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R856_FrpcPublicTcp7000SynThenPayloadRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PrivatePublic(r) || !Research676Evidence.Process(r,"frpc.exe","frpc") || r.DestinationPort != 7000) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (Research676Evidence.Syn(r)) { _stages.Observe(key,r.Id,context.TimestampUtc,true,30); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || r.L4Len is < 512 or > 4096 || !_stages.Observe(key,r.Id,context.TimestampUtc,false,30)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R2865","owner-research"),
                new DetectionEvidenceItem("matched_conditions","frpc_public_7000_syn_then_payload","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Frpc public TCP/7000 SYN then payload observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:2,windowSeconds:30);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
