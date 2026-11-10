// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R2691.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R857_AwkUnusualPublicTlsPayloadRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R857", Name: "Awk-attributed public TLS/8443 medium payload", Category: "EvasionInfra",
            Description: "An awk-attributed public TLS/8443 TCP payload has 720–820 bytes; process command line, decoded scripts and asset role are unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R857.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R857", Name = "Awk-attributed public TLS/8443 medium payload", Category = "EvasionInfra",
            Description = "workbook.R2691: An awk-attributed public TLS/8443 TCP payload has 720–820 bytes; process command line, decoded scripts and asset role are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "awk_public_tls8443_medium_payload", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        
        public R857_AwkUnusualPublicTlsPayloadRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord r) =>
            !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni)
            && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null
            && r.DnsQname == null && !r.DnsIsResponse
            && !string.Equals(r.ApplicationProtocol,"HTTP",StringComparison.OrdinalIgnoreCase)
            && !string.Equals(r.ApplicationProtocol,"DNS",StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) || !Research676Evidence.Process(r,"awk","awk.exe") || r.DestinationPort != 8443 || r.L4Len is < 720 or > 820 || !ValidTls(r)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R2691","owner-research"),
                new DetectionEvidenceItem("matched_conditions","awk_public_tls8443_medium_payload","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Awk-attributed public TLS/8443 medium payload observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:1,windowSeconds:60);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
