// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no build/test execution. workbook.R2476.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R921_AnydeskPublic6568ThenTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R921", Name: "AnyDesk public TCP/6568 SYN then same-peer TLS", Category: "CommandAndControl",
            Description: "Same private source, AnyDesk PID and public peer TCP/6568 SYN followed by TLS/443 data. Installation path, interactive control, consent and session outcome are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R921.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R921", Name = "AnyDesk public TCP/6568 SYN then same-peer TLS", Category = "CommandAndControl",
            Description = "workbook.R2476: Same private source, AnyDesk PID and public peer TCP/6568 SYN followed by TLS/443 data. Installation path, interactive control, consent and session outcome are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same private source, AnyDesk PID and public peer TCP/6568 SYN followed by TLS/443 data. Installation path, interactive control, consent and session outcome are unknown.", "Coherent typed IPv4 fields and bounded UTC observations." },
            NegativeConditions = new[] { "Missing or contradictory evidence, mismatched keys, duplicate packet IDs, reverse UTC and expired windows fail closed.",
                "No unsupported host identity, execution, authentication, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, diagnostics, software deployment, maintenance and security testing can share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R921_AnydeskPublic6568ThenTlsRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC",
                "correlation expiry and key isolation", "cooldown recovery", "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R921_AnydeskPublic6568ThenTlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 6568 && Research676Evidence.Process(r, "anydesk.exe", "anydesk") && Research676Evidence.Syn(r) && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse;
            var second = Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 443 && Research676Evidence.Process(r, "anydesk.exe", "anydesk") && Research786NetworkEvidence.TcpData(r) && !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && !r.DnsIsResponse;
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2476", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R921_AnydeskPublic6568ThenTlsRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "AnyDesk public TCP/6568 SYN then same-peer TLS observed; authorization, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
