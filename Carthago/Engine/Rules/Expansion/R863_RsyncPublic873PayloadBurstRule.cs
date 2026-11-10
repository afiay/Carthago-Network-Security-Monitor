// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1519.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R863_RsyncPublic873PayloadBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R863", Name: "Rsync-attributed public TCP/873 payload burst", Category: "Exfiltration",
            Description: "Five rsync-attributed TCP/873 packets to one public peer within 30s have at least 10000 payload bytes; file read and successful sync not observed.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R863.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R863", Name = "Rsync-attributed public TCP/873 payload burst", Category = "Exfiltration",
            Description = "workbook.R1519: Five rsync-attributed TCP/873 packets to one public peer within 30s have at least 10000 payload bytes; file read and successful sync not observed.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 5, Window = TimeSpan.FromSeconds(30), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "rsync_public_873_payload_burst", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _count = new();
        public R863_RsyncPublic873PayloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r,"rsync","rsync.exe")
                || r.DestinationPort != 873 || r.L4Len is < 1800 or > 4096
                || r.TlsVersion != null || r.Sni != null || r.DnsQname != null
                || r.HttpMethod != null || r.ApplicationProtocol != null) return NoMatch();
            var key = r.Source!+"|"+r.Destination!+"|"+r.ProcessId;
            if (!_count.Observe(key,r.Id,r.L4Len!.Value,context.TimestampUtc,5,30,10000)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R1519","owner-research"),
                new DetectionEvidenceItem("matched_conditions","rsync_public_873_payload_burst","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Rsync-attributed public TCP/873 payload burst observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:5,windowSeconds:30);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
