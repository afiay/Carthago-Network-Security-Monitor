// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2952.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R865_CurlCmdGetThenCmdPublicSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R865", Name: "Curl CMD-file GET followed by cmd-attributed public SYN", Category: "Execution",
            Description: "Curl-attributed HTTP/80 .cmd GET precedes cmd-attributed TCP/8443 SYN to another public peer within 60s; file execution, shell ancestry and download success unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R865.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R865", Name = "Curl CMD-file GET followed by cmd-attributed public SYN", Category = "Execution",
            Description = "workbook.R2952: Curl-attributed HTTP/80 .cmd GET precedes cmd-attributed TCP/8443 SYN to another public peer within 60s; file execution, shell ancestry and download success unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "curl_cmd_get_then_cmd_public_syn", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();
        public R865_CurlCmdGetThenCmdPublicSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r)
                && Research676Evidence.Process(r,"curl.exe") && r.DestinationPort == 80
                && WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
                && method == "GET" && uri.EndsWith(".cmd",StringComparison.OrdinalIgnoreCase))
            { _peers.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc,true); return NoMatch(); }
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r)
                || !Research786NetworkEvidence.PrivatePublic(r) || !Research676Evidence.Process(r,"cmd.exe")
                || r.DestinationPort != 8443
                || !_peers.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc,false)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R2952","owner-research"),
                new DetectionEvidenceItem("matched_conditions","curl_cmd_get_then_cmd_public_syn","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Curl CMD-file GET followed by cmd-attributed public SYN observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:2,windowSeconds:60);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
