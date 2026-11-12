// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1906; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R930_MsbuildTargetsGetThenPublicSmbRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R930", Name: "MSBuild public targets GET then public SMB SYN", Category: "EvasionInfra",
            Description: "Same local MSBuild PID retrieves a .targets path over cleartext public HTTP then initiates TCP/445 to a public peer. Build execution, downloaded contents and SMB authentication are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R930.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R930", Name = "MSBuild public targets GET then public SMB SYN", Category = "EvasionInfra",
            Description = "workbook.R1906: Same local MSBuild PID retrieves a .targets path over cleartext public HTTP then initiates TCP/445 to a public peer. Build execution, downloaded contents and SMB authentication are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "http.method", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same local MSBuild PID retrieves a .targets path over cleartext public HTTP then initiates TCP/445 to a public peer. Build execution, downloaded contents and SMB authentication are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R930_MsbuildTargetsGetThenPublicSmbRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R930_MsbuildTargetsGetThenPublicSmbRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 80 && Research676Evidence.Process(r, "msbuild.exe", "msbuild") && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "GET" && (uri.Split('?')[0].EndsWith(".targets", StringComparison.OrdinalIgnoreCase)) && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253;
            var second = Research676Evidence.Syn(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 445 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && Research676Evidence.Process(r, "msbuild.exe", "msbuild");
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1906", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R930_MsbuildTargetsGetThenPublicSmbRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "MSBuild public targets GET then public SMB SYN observed; authorization, causality and outcome remain unverified.", evidence,
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
