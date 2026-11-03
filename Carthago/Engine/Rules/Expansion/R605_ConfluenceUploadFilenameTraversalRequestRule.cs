// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero tests/builds executed.
// Original workbook research: R3041. Request-only classification, not exploitation evidence.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R605_ConfluenceUploadFilenameTraversalRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R605",
            Name: "Confluence upload.action filename traversal POST",
            Category: "HttpApi",
            Description: "Confluence upload.action POST with multi-level filename parameter traversal; file-write outcome unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R605.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R605", Name = "Confluence upload.action filename traversal POST", Category = "HttpApi",
            Description = "Confluence upload.action POST with multi-level filename parameter traversal; file-write outcome unknown.", Severity = SeverityLevel.High,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination_or_host", "http.method", "http.uri", "protocol_or_port" },
            EvidenceFields = new[] { "http.signature", "http.method", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require a bounded parser-labeled cleartext HTTP request with coherent IP/TCP metadata.",
                "Match the independent rule-specific HTTP method/URI/header conjunction only.",
                "Request signature never establishes exploitation, compromised host or server response."
            },
            NegativeConditions = new[]
            {
                "No port-only, Info-only, other protocol, TLS, DNS/Redis, or synthetic evidence assertions.",
                "Reject missing required fields, malformed requests, benign near misses, duplicates and old timestamps.",
                "Never assert successful authentication, command execution, disclosure or persistence."
            },
            FalsePositives = new[] { "Authorized scanner, replay, attack simulation and maintenance traffic can resemble this request." },
            MinimumConfidence = 84, WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "one_specific_method_uri_headers_request_per_exact_source_destination",
            TuningKnobs = new[] { "Mode", "ApprovedMaintenanceWindows", "ApprovedScanners" },
            RequiredTests = new[]
            {
                "exact request positive and benign near miss negative",
                "wrong method and missing or contradictory parser fields",
                "duplicate ID, out-of-order timestamp, cooldown and bounded state",
                "redacted structured evidence and no server outcome inference",
                "candidate shadow mode and unique sequential registry entry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        public R605_ConfluenceUploadFilenameTraversalRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(record, out var method, out var uri)
                || !SignatureMatches(method, uri, record.HttpUserAgent, record.HttpRequestHeaders))
                return NoMatch();

            var observed = _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
            if (observed == WebSignatureObservation.None) return NoMatch();
            if (observed == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("http.signature", "workbook.R3041.request_shape", "http-request-fields"),
                new DetectionEvidenceItem("http.method", method, "http-request-fields"),
                new DetectionEvidenceItem("matched_conditions", "specific_http_request_shape", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Specific suspicious HTTP request shape observed; response and exploitation outcome unknown",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.43, "structured-http-request");
                    confidence.AddEvidence(0.36, "rule-specific-request-signature");
                    confidence.AddCorrelation(0.12, "coherent-network-metadata");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool SignatureMatches(string method, string uri, string? userAgent, string? headers)
        {
            var mark = uri.IndexOf('?');
            var path = mark >= 0 ? uri.Substring(0, mark) : uri;
            var query = mark >= 0 ? uri.Substring(mark + 1) : string.Empty;
            return string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase)
                && path.Contains("/upload.action", StringComparison.OrdinalIgnoreCase)
                && query.Contains("filename=../../../../", StringComparison.OrdinalIgnoreCase);
        }
    }
}
