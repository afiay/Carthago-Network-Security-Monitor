// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit tests authored, 0 executed.
// Workbook research R3053; observed cleartext request shape, NOT exploitation outcome.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R595_GrafanaPluginTraversalRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R595",
            Name: "Grafana plugin traversal request",
            Category: "HttpApi",
            Description: "Grafana plugin path with repeated dot-dot segments; file disclosure unproven.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R595.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R595", Name = "Grafana plugin traversal request",
            Category = "HttpApi", Description = "Grafana plugin path with repeated dot-dot segments; file disclosure unproven.",
            Severity = SeverityLevel.High, Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination_or_host", "http.method", "http.uri", "protocol_or_port" },
            EvidenceFields = new[] { "http.signature", "http.method", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Parsed cleartext HTTP request must match its exact rule-specific URL/method predicate.",
                "Coherent TCP/IP and bounded HTTP request metadata; distinct source and destination required.",
                "Only the HTTP request shape is asserted; no successful exploit, server state or CVE outcome."
            },
            NegativeConditions = new[]
            {
                "Reject absent parser fields, free-form Info-only text, malformed URI, TLS, DNS/Redis contradictions.",
                "Reject benign near-miss URI/method and duplicated or out-of-order evidence.",
                "Never infer successful access, command execution or exfiltration from request-only observations."
            },
            FalsePositives = new[] { "Authorized assessment, replay and maintenance requests can match this signature." },
            MinimumConfidence = 84, WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(5), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "exact_source+exact_destination+single_specific_request_signature",
            TuningKnobs = new[] { "Mode", "ApprovedMaintenanceWindows", "ApprovedScanners" },
            RequiredTests = new[]
            {
                "positive method and exact request shape; negative benign near miss",
                "wrong method, missing or contradictory parser fields",
                "duplicate evidence, out-of-order, cooldown and bounded keys",
                "redacted event evidence and no exploit-success claim",
                "candidate Shadow mode and sequential registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        public R595_GrafanaPluginTraversalRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(record, out var method, out var uri)
                || !SignatureMatches(method, uri))
                return NoMatch();
            var observation = _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
            if (observation == WebSignatureObservation.None) return NoMatch();
            if (observation == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("http.signature", "workbook.R3053.request_shape", "parsed-cleartext-http"),
                new DetectionEvidenceItem("http.method", method, "http-parser"),
                new DetectionEvidenceItem("matched_conditions", "typed_http_request,exact_signature", "rule"),
                new DetectionEvidenceItem("outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Specific suspicious cleartext HTTP request pattern observed; server outcome unknown",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.42, "parsed-http-application-protocol");
                    confidence.AddEvidence(0.36, "exact-signature-specific-method-uri");
                    confidence.AddCorrelation(0.12, "coherent-tcp-endpoints");
                }, count: 1, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool SignatureMatches(string method, string uri)
        {
            var delimiter = uri.IndexOf('?');
            var path = delimiter >= 0 ? uri.Substring(0, delimiter) : uri;
            var query = delimiter >= 0 ? uri.Substring(delimiter + 1) : string.Empty;
            if (!path.Contains("/public/plugins/", StringComparison.OrdinalIgnoreCase)) return false;
var pos = path.IndexOf("/public/plugins/", StringComparison.OrdinalIgnoreCase) + "/public/plugins/".Length;
var tail = path.Substring(pos);
var sep = tail.IndexOf('/');
if (sep <= 0) return false;
var plugin = tail.Substring(0, sep);
if (!IsKnownPlugin(plugin)) return false;
var count = 0;
var offset = sep;
while ((offset = tail.IndexOf("../", offset, StringComparison.Ordinal)) >= 0)
{
    count++;
    offset += 3;
}
return count >= 4;
        }

        private static bool IsKnownPlugin(string name)
            => name.Equals("live", StringComparison.OrdinalIgnoreCase)
            || name.Equals("loki", StringComparison.OrdinalIgnoreCase)
            || name.Equals("grafana", StringComparison.OrdinalIgnoreCase)
            || name.Equals("mysql", StringComparison.OrdinalIgnoreCase)
            || name.Equals("postgres", StringComparison.OrdinalIgnoreCase)
            || name.Equals("prometheus", StringComparison.OrdinalIgnoreCase)
            || name.Equals("graph", StringComparison.OrdinalIgnoreCase)
            || name.Equals("table", StringComparison.OrdinalIgnoreCase)
            || name.Equals("alertmanager", StringComparison.OrdinalIgnoreCase);
    }
}
