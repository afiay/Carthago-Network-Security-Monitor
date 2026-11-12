// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1806; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R940_TeamviewerPublic5938TlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R940", Name: "TeamViewer public TLS/5938 vendor-name contact", Category: "CommandAndControl",
            Description: "TeamViewer-attributed public TLS/5938 with SNI equal to teamviewer.com or its subdomain. Remote control session, installation provenance, persistence and consent are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R940.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R940", Name = "TeamViewer public TLS/5938 vendor-name contact", Category = "CommandAndControl",
            Description = "workbook.R1806: TeamViewer-attributed public TLS/5938 with SNI equal to teamviewer.com or its subdomain. Remote control session, installation provenance, persistence and consent are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "TeamViewer-attributed public TLS/5938 with SNI equal to teamviewer.com or its subdomain. Remote control session, installation provenance, persistence and consent are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R940_TeamviewerPublic5938TlsRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R940_TeamviewerPublic5938TlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!(Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 5938 && Research676Evidence.Process(r, "teamviewer.exe", "teamviewer", "teamviewer_service.exe", "teamviewer_service") && !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && !r.DnsIsResponse && (string.Equals(r.Sni, "teamviewer.com", StringComparison.OrdinalIgnoreCase) || r.Sni!.EndsWith(".teamviewer.com", StringComparison.OrdinalIgnoreCase)))) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1806", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R940_TeamviewerPublic5938TlsRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "TeamViewer public TLS/5938 vendor-name contact observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
