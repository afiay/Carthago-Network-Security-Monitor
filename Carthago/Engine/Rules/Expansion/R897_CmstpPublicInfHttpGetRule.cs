// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R1756.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R897_CmstpPublicInfHttpGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R897", Name: "CMSTP-attributed public HTTP INF GET", Category: "HttpApi",
            Description: "Local cmstp attribution and a public HTTP GET ending in .inf; profile installation, command line, DLL load and privilege change are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R897.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R897", Name = "CMSTP-attributed public HTTP INF GET", Category = "HttpApi",
            Description = "workbook.R1756: Local cmstp attribution and a public HTTP GET ending in .inf; profile installation, command line, DLL load and privilege change are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "process.id", "process.name", "http.uri", "http.host", "http.method" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and source-specific local process association.", "Bounded UTC evidence where correlation is required." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong process or direction, duplicates or stale evidence fail closed.",
                "No unobserved endpoint execution, authorization, authentication, decrypted contents or security outcome asserted." },
            FalsePositives = new[] { "Approved administration, software deployment, diagnostics and routine infrastructure activity can match." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "cmstp_public_http_inf_get",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        
        public R897_CmstpPublicInfHttpGetRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "cmstp.exe", "cmstp") || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !uri.Split('?')[0].EndsWith(".inf", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1756", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "cmstp_public_http_inf_get", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "CMSTP-attributed public HTTP INF GET observed; authorization, causality and security outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "source_specific_workbook_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
