// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1398.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R861_ThunderbirdZipGetThenBashTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R861", Name: "Thunderbird ZIP GET followed by bash TLS to another peer", Category: "Execution",
            Description: "A thunderbird-attributed cleartext .zip GET precedes bash-attributed public TLS/8443 to a different peer inside 60s; attachment opening and process lineage unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R861.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R861", Name = "Thunderbird ZIP GET followed by bash TLS to another peer", Category = "Execution",
            Description = "workbook.R1398: A thunderbird-attributed cleartext .zip GET precedes bash-attributed public TLS/8443 to a different peer inside 60s; attachment opening and process lineage unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "thunderbird_zip_get_then_bash_tls_other_peer", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research806DifferentPeerWindow _peers = new();
        public R861_ThunderbirdZipGetThenBashTlsRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord r) =>
            !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni)
            && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null
            && r.DnsQname == null && !r.DnsIsResponse
            && !string.Equals(r.ApplicationProtocol,"HTTP",StringComparison.OrdinalIgnoreCase)
            && !string.Equals(r.ApplicationProtocol,"DNS",StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r)
                && Research676Evidence.Process(r,"thunderbird.exe","thunderbird")
                && r.DestinationPort == 80
                && WebSignatureRequestEvidence.TryGet(r,out var method,out var uri)
                && method == "GET" && uri.Contains(".zip",StringComparison.OrdinalIgnoreCase))
            { _peers.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc,true); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r,"bash","bash.exe")
                || r.DestinationPort != 8443 || r.L4Len is < 512 or > 4096
                || !ValidTls(r) || !_peers.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc,false)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R1398","owner-research"),
                new DetectionEvidenceItem("matched_conditions","thunderbird_zip_get_then_bash_tls_other_peer","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Thunderbird ZIP GET followed by bash TLS to another peer observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:2,windowSeconds:60);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
