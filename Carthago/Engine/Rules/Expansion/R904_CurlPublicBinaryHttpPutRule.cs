// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero builds/tests executed. workbook.R2375.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R904_CurlPublicBinaryHttpPutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R904", Name: "Curl public binary HTTP PUT request", Category: "Exfiltration",
            Description: "Local curl attribution and a public cleartext HTTP PUT with exact application/octet-stream content-type, typed request and at least 512 transport payload bytes; file contents, upload completion and exfiltration are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R904.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R904", Name = "Curl public binary HTTP PUT request", Category = "Exfiltration",
            Description = "workbook.R2375: Local curl attribution and a public cleartext HTTP PUT with exact application/octet-stream content-type, typed request and at least 512 transport payload bytes; file contents, upload completion and exfiltration are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "destination.port", "packet.id", "process.id", "process.name", "http.method", "http.uri", "http.request.headers" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Coherent typed IPv4 packet and specific process attribution where required.", "Ordered independent UTC observations where correlation applies." },
            NegativeConditions = new[] { "Missing or contradictory typed evidence, wrong endpoint, duplicate IDs, reverse UTC and expired correlation fail closed.",
                "No unsupported authentication, execution, file access, authorization or causality inferred." },
            FalsePositives = new[] { "Approved administration, diagnostics, maintenance and software deployment can match." },
            MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "curl_public_http_put_binary_content_type",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory evidence",
                "duplicate IDs and reverse UTC", "correlation expiry and key isolation where applicable", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        public R904_CurlPublicBinaryHttpPutRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !Research676Evidence.Process(r, "curl.exe", "curl") || r.DestinationPort != 80
                || r.L4Len is < 512 || !WebSignatureRequestEvidence.TryGet(r, out var method, out _, allowPut: true)
                || method != "PUT" || r.HttpRequestHeaders is not { Length: > 0 and <= 4096 } headers)
                return NoMatch();
            var binary = false;
            var contentTypes = 0;
            foreach (var line in headers.Split('\n'))
            {
                var colon = line.IndexOf(':');
                if (colon < 0 || !string.Equals(line.Substring(0, colon).Trim(), "Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                contentTypes++;
                binary = string.Equals(line.Substring(colon + 1).Trim(), "application/octet-stream", StringComparison.OrdinalIgnoreCase);
            }
            if (contentTypes != 1 || !binary) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2375", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "curl_public_http_put_binary_content_type", "rule"),
                new DetectionEvidenceItem("outcome", "typed_network_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Curl public binary HTTP PUT request observed; authorization, causality and security outcome remain unverified.",
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
