// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1706.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R900_RegasmPublicSynThenTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R900", Name: "Regasm or Regsvcs-attributed public SYN then TLS data", Category: "EvasionInfra",
            Description: "Same private source, public peer, local regasm/regsvcs PID and source port SYN to TCP/443 followed by TLS-marked TCP data in 45 seconds; COM registration, assembly load, execution and C2 are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R900.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R900", Name = "Regasm or Regsvcs-attributed public SYN then TLS data", Category = "EvasionInfra",
            Description = "workbook.R1706: Same private source, public peer, local regasm/regsvcs PID and source port SYN to TCP/443 followed by TLS-marked TCP data in 45 seconds; COM registration, assembly load, execution and C2 are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "tcp.flags", "packet.id", "process.id", "process.name", "tls.sni", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and source-specific local process association.", "Bounded UTC evidence where correlation is required." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong process or direction, duplicates or stale evidence fail closed.",
                "No unobserved endpoint execution, authorization, authentication, decrypted contents or security outcome asserted." },
            FalsePositives = new[] { "Approved administration, software deployment, diagnostics and routine infrastructure activity can match." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "regasm_regsvcs_public_syn_then_same_flow_tls",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R900_RegasmPublicSynThenTlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "regasm.exe", "regasm", "regsvcs.exe", "regsvcs")
                || r.DestinationPort != 443 || r.HttpMethod != null || r.HttpUri != null
                || r.DnsQname != null || r.DnsIsResponse) return NoMatch();
            var first = Research676Evidence.Syn(r) && r.Sni == null;
            var second = Research786NetworkEvidence.TcpData(r) && !string.IsNullOrWhiteSpace(r.TlsVersion)
                && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.SourcePort + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1706", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "regasm_regsvcs_public_syn_then_same_flow_tls", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Regasm or Regsvcs-attributed public SYN then TLS data observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
