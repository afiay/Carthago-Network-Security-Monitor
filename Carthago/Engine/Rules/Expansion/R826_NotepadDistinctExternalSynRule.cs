// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests executed. workbook.R2237.
using System;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R826_NotepadDistinctExternalSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R826", Name: "Notepad-attributed SYNs to two distinct public peers", Category: "EvasionInfra",
            Description: "The local Notepad process has two separate outbound TCP SYN attempts; code injection, execution and connection success are unknown.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R826.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R826", Name = "Notepad-attributed SYNs to two distinct public peers", Category = "EvasionInfra",
            Description = "workbook.R2237: The local Notepad process has two separate outbound TCP SYN attempts; code injection, execution and connection success are unknown.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
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
            Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "notepad_distinct_public_syn",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "specific positive/benign case", "missing/contradictory evidence", "duplicate/reverse/expiry",
                "cooldown recovery", "raw Info excluded", "non-convergence", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R826_NotepadDistinctExternalSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research676Evidence.Syn(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || r.DestinationPort is not (443 or 8443)
                || !Research676Evidence.Process(r, "notepad.exe")
                || !_distinct.Observe(r.Source! + "|" + r.ProcessId,
                    r.Destination!, r.Id, context.TimestampUtc, 2, 45))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2237", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "notepad_distinct_public_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Notepad-attributed SYNs to two distinct public peers observed; authorization, provenance and outcomes unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_and_optional_local_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_derived_narrow_predicate");
                    confidence.AddCorrelation(0.12, "coherent_endpoints_and_bounded_time");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
        
    }
}

