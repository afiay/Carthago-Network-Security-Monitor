// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R1800; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R952_WscriptPublicVbsGetThenTlsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R952", Name: "Wscript public VBS GET then same-PID public TLS", Category: "EvasionInfra",
            Description: "Wscript PID retrieves a public .vbs path then sends public TLS/443 data. SyncAppvPublishingServer invocation, embedded PowerShell, script content and execution are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R952.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R952", Name = "Wscript public VBS GET then same-PID public TLS", Category = "EvasionInfra",
            Description = "workbook.R1800: Wscript PID retrieves a public .vbs path then sends public TLS/443 data. SyncAppvPublishingServer invocation, embedded PowerShell, script content and execution are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http, RuleTelemetryKind.Tls },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name", "http.method", "http.uri", "http.host", "tls.version", "tls.sni" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Wscript PID retrieves a public .vbs path then sends public TLS/443 data. SyncAppvPublishingServer invocation, embedded PowerShell, script content and execution are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R952_WscriptPublicVbsGetThenTlsRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R952_WscriptPublicVbsGetThenTlsRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 80 && Research676Evidence.Process(r, "wscript.exe", "wscript") && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "GET" && (uri.Split('?')[0].EndsWith(".vbs", StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253;
            var second = Research786NetworkEvidence.PrivatePublic(r) && Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 443 && !string.IsNullOrWhiteSpace(r.TlsVersion) && !string.IsNullOrWhiteSpace(r.Sni) && r.Sni.Length <= 253 && r.HttpMethod == null && r.HttpUri == null && r.DnsQname == null && !r.DnsIsResponse && Research676Evidence.Process(r, "wscript.exe", "wscript");
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1800", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R952_WscriptPublicVbsGetThenTlsRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Wscript public VBS GET then same-PID public TLS observed; authorization, causality and outcome remain unverified.", evidence,
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
