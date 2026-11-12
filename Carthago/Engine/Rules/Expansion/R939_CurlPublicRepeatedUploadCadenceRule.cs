// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. workbook.R1444; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R939_CurlPublicRepeatedUploadCadenceRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R939", Name: "Curl public HTTP POST cadence", Category: "Exfiltration",
            Description: "Same private curl PID and public HTTP host/path sends four POST records of 512–4096 transport bytes at 5–20s intervals within 65s. Scheduled task, file contents and transfer completion are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R939.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R939", Name = "Curl public HTTP POST cadence", Category = "Exfiltration",
            Description = "workbook.R1444: Same private curl PID and public HTTP host/path sends four POST records of 512–4096 transport bytes at 5–20s intervals within 65s. Scheduled task, file contents and transfer completion are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "tcp.flags", "process.id", "process.name", "http.method", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same private curl PID and public HTTP host/path sends four POST records of 512–4096 transport bytes at 5–20s intervals within 65s. Scheduled task, file contents and transfer completion are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported endpoint action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 4, Window = TimeSpan.FromSeconds(65),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R939_CurlPublicRepeatedUploadCadenceRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CadenceWindow _cadence = new();
        public R939_CurlPublicRepeatedUploadCadenceRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            if (!(Research786NetworkEvidence.TcpData(r) && Research786NetworkEvidence.PrivatePublic(r) && r.DestinationPort == 80 && Research676Evidence.Process(r, "curl.exe", "curl") && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri) && method == "POST" && (r.L4Len >= 512 && r.L4Len <= 4096) && !string.IsNullOrWhiteSpace(r.HttpHost) && r.HttpHost.Length <= 253)) return NoMatch();
            if (!_cadence.Observe(r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + r.HttpHost!.ToLowerInvariant() + "|" + uri.Split('?')[0], r.Id, r.L4Len!.Value, context.TimestampUtc, 4, 5, 20, 256, 65)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1444", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R939_CurlPublicRepeatedUploadCadenceRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Curl public HTTP POST cadence observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 4, windowSeconds: 65);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
