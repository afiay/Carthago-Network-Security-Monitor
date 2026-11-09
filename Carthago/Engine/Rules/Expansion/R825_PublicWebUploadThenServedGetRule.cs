// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit source authored first, 0 tests executed; workbook.R1553.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R825_PublicWebUploadThenServedGetRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R825",
            Name: "Public image upload POST then matching served-path GET",
            Category: "WebThreat",
            Description: "Public image-upload POST followed by same-source matching served-path GET. No file modification, defacement or upload success inferred.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R825.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R825",
            Name = "Public image upload POST then matching served-path GET",
            Category = "WebThreat",
            Description = "workbook.R1553: Matching client HTTP paths do not establish server-side writes, content replacement, a vulnerable upload handler or defacement.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "packet.id", "http.method", "http.uri", "http.host" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Strict typed transport, coherent direction, unique packet IDs and the independent source predicate.",
                "Bounded instance-owned UTC correlation state; no live producer or replay quality claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reverse-time events and expired evidence fail closed.",
                "No inferred local file, identity, configuration, credential, success or compromise event."
            },
            FalsePositives = new[]
            {
                "Authorized administration, CI/CD, diagnostics, inventory and software upgrades may show these network patterns."
            },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "R825_public_upload_post_then_matching_get",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] {
                "positive/benign", "missing/contradictory fields", "replay/reverse/expiry",
                "cooldown", "evidence privacy", "Candidate Shadow", "independent registry identity"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _sequence = new();

        public R825_PublicWebUploadThenServedGetRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253)
                return NoMatch();
            var upload = method == "POST" && uri.StartsWith("/upload/", StringComparison.OrdinalIgnoreCase);
            var served = method == "GET" && uri.StartsWith("/uploads/", StringComparison.OrdinalIgnoreCase);
            if (!upload && !served) return NoMatch();
            var suffix = uri.Substring(upload ? "/upload/".Length : "/uploads/".Length);
            if (suffix.Length is < 5 or > 100 || suffix.Contains('/')
                || suffix.Contains("..", StringComparison.Ordinal)
                || !(suffix.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
                    || suffix.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase)))
                return NoMatch();
            var key = r.Source! + "|" + r.Destination + "|" + r.HttpHost.ToLowerInvariant()
                + "|" + suffix.ToLowerInvariant();
            if (!_sequence.Observe(key, r.Id, context.TimestampUtc, upload, 90))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1553", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "r825_public_upload_post_then_matching_get", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public image upload POST followed by matching-path GET observed; file write, server response and impact unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "typed_packet_or_process_fields");
                    confidence.AddEvidence(0.33, "independent_workbook_source_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_correlation");
                },
                count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
