// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R2053; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R936_PythonPublicTlsCertificateValidityInversionRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R936", Name: "Python public TLS SYN then inverted certificate validity", Category: "EvasionInfra",
            Description: "Python-attributed public TCP/443 SYN followed by reverse-flow certificate metadata with NotAfter earlier than NotBefore. Parser observation only; certificate verification, acceptance, crypto library and compromise are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R936.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R936", Name = "Python public TLS SYN then inverted certificate validity", Category = "EvasionInfra",
            Description = "workbook.R2053: Python-attributed public TCP/443 SYN followed by reverse-flow certificate metadata with NotAfter earlier than NotBefore. Parser observation only; certificate verification, acceptance, crypto library and compromise are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "tls.version" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Python-attributed public TCP/443 SYN followed by reverse-flow certificate metadata with NotAfter earlier than NotBefore. Parser observation only; certificate verification, acceptance, crypto library and compromise are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R936_PythonPublicTlsCertificateValidityInversionRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R936_PythonPublicTlsCertificateValidityInversionRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research676Evidence.Syn(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 443 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && Research676Evidence.Process(r, "python", "python3", "python.exe");
            var second = Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PublicPrivate(r) && r.SourcePort == 443 && !string.IsNullOrWhiteSpace(r.TlsVersion) && r.CertValidFrom is DateTime start && r.CertValidTo is DateTime end && start.Kind == DateTimeKind.Utc && end.Kind == DateTimeKind.Utc && end < start && r.HttpMethod == null && r.DnsQname == null;
            if (!first && !second) return NoMatch();
            var key = first ? r.Source! + "|" + r.Destination! + "|" + r.SourcePort : r.Destination! + "|" + r.Source! + "|" + r.DestinationPort;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2053", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R936_PythonPublicTlsCertificateValidityInversionRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Python public TLS SYN then inverted certificate validity observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
