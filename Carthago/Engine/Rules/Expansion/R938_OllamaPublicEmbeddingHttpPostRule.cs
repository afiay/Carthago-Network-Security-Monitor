// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1290; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R938_OllamaPublicEmbeddingHttpPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R938", Name: "Ollama public embedding API HTTP POST", Category: "Exfiltration",
            Description: "Ollama-attributed cleartext public POST to /api/embed or /api/embeddings on TCP/11434 with at least 512 transport bytes. Input contents, sensitive data, AI policy and exfiltration are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R938.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R938", Name = "Ollama public embedding API HTTP POST", Category = "Exfiltration",
            Description = "workbook.R1290: Ollama-attributed cleartext public POST to /api/embed or /api/embeddings on TCP/11434 with at least 512 transport bytes. Input contents, sensitive data, AI policy and exfiltration are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "http.method", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Ollama-attributed cleartext public POST to /api/embed or /api/embeddings on TCP/11434 with at least 512 transport bytes. Input contents, sensitive data, AI policy and exfiltration are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R938_OllamaPublicEmbeddingHttpPostRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R938_OllamaPublicEmbeddingHttpPostRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!(Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 11434 && Research676Evidence.Process(r, "ollama", "ollama.exe") && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "POST" && ((uri.Split('?')[0] == "/api/embed" || uri.Split('?')[0] == "/api/embeddings") && r.L4Len >= 512) && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1290", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R938_OllamaPublicEmbeddingHttpPostRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Ollama public embedding API HTTP POST observed; authorization, causality and outcome remain unverified.", evidence,
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
