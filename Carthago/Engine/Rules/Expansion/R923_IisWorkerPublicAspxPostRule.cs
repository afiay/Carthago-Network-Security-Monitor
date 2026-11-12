// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Test source authored first; no build/test execution. workbook.R1180.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R923_IisWorkerPublicAspxPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R923", Name: "IIS worker public ASPX HTTP POST", Category: "CommandAndControl",
            Description: "Local w3wp attribution and outbound public HTTP POST to an .aspx path with at least 512 transport bytes. IIS module installation, contents, persistence and C2 are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R923.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R923", Name = "IIS worker public ASPX HTTP POST", Category = "CommandAndControl",
            Description = "workbook.R1180: Local w3wp attribution and outbound public HTTP POST to an .aspx path with at least 512 transport bytes. IIS module installation, contents, persistence and C2 are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "http.method", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Local w3wp attribution and outbound public HTTP POST to an .aspx path with at least 512 transport bytes. IIS module installation, contents, persistence and C2 are unknown.", "Coherent typed IPv4 fields and bounded UTC observations." },
            NegativeConditions = new[] { "Missing or contradictory evidence, mismatched keys, duplicate packet IDs, reverse UTC and expired windows fail closed.",
                "No unsupported host identity, execution, authentication, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, diagnostics, software deployment, maintenance and security testing can share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R923_IisWorkerPublicAspxPostRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC",
                "correlation expiry and key isolation", "cooldown recovery", "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R923_IisWorkerPublicAspxPostRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!(Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 80 && Research676Evidence.Process(r, "w3wp.exe", "w3wp") && Research786NetworkEvidence.TcpData(r) && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "POST" && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253 && (uri.Split('?')[0].EndsWith(".aspx", StringComparison.OrdinalIgnoreCase)) && r.L4Len >= 512)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1180", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R923_IisWorkerPublicAspxPostRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "IIS worker public ASPX HTTP POST observed; authorization, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
