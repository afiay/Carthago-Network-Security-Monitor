// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1265.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R859_PublicSshIngressThenEsxcliPublicTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R859", Name: "Public SSH ingress then esxcli-attributed TLS egress", Category: "LateralMovement",
            Description: "Public SSH/22 inbound SYN then esxcli-attributed public TLS/8443 from same private host within 60s; no login, host role or command proven.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R859.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R859", Name = "Public SSH ingress then esxcli-attributed TLS egress", Category = "LateralMovement",
            Description = "workbook.R1265: Public SSH/22 inbound SYN then esxcli-attributed public TLS/8443 from same private host within 60s; no login, host role or command proven.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "packet.id", "process.id", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed packet fields and an independent narrow predicate.", "Per-rule bounded UTC observation; no security outcome inferred." },
            NegativeConditions = new[] { "Missing/contradictory typed fields, duplicate IDs, reverse UTC and expired observations fail closed.", "No command execution, authenticated identity, decrypted payload, authorization or compromise inferred." },
            FalsePositives = new[] { "Authorized operations, diagnostics, update traffic, process attribution errors and sanctioned testing may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_ssh_ingress_then_esxcli_tls", TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed fixtures", "missing/contradictory evidence", "duplicate and expired observations", "cooldown recovery", "raw Info exclusion", "neighbor independence", "Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R859_PublicSshIngressThenEsxcliPublicTlsRule() : base(Rule, Profile) { }

        private static bool ValidTls(TrafficRecord r) =>
            !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni)
            && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null
            && r.DnsQname == null && !r.DnsIsResponse
            && !string.Equals(r.ApplicationProtocol,"HTTP",StringComparison.OrdinalIgnoreCase)
            && !string.Equals(r.ApplicationProtocol,"DNS",StringComparison.OrdinalIgnoreCase);

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.Coherent(r) && Research676Evidence.Syn(r) && Research786NetworkEvidence.PublicPrivate(r) && r.DestinationPort == 22)
            { _stages.Observe(r.Destination!,r.Id,context.TimestampUtc,true,60); return NoMatch(); }
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r) || !Research676Evidence.Process(r,"esxcli","esxcli.exe") || r.DestinationPort != 8443 || r.L4Len is < 512 or > 4096 || !ValidTls(r) || !_stages.Observe(r.Source!,r.Id,context.TimestampUtc,false,60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!,r.Destination!,r.Id,context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier","workbook.R1265","owner-research"),
                new DetectionEvidenceItem("matched_conditions","public_ssh_ingress_then_esxcli_tls","rule"),
                new DetectionEvidenceItem("outcome","typed_packet_shape_only_causality_and_impact_unknown","rule")
            };
            var evt = CreateDetectionEvent(context,SeverityLevel.Medium,
                "Public SSH ingress then esxcli-attributed TLS egress observed; provenance, authorization, causality and security outcome unverified.",
                evidence,confidence => {
                    confidence.AddEvidence(0.45,"coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33,"independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12,"bounded_monotonic_utc_observation");
                },count:2,windowSeconds:60);
            return RuleEvaluationResult.Match(Descriptor.RuleId,evt);
        }
    }
}
