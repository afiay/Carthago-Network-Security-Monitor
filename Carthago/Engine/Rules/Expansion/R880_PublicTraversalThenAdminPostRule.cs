// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1390.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R880_PublicTraversalThenAdminPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R880", Name: "Public CGI traversal GET followed by admin upload POST", Category: "WebThreat",
            Description: "One public client sends GET to /cgi-bin/.%2e/ followed by POST to /admin/upload on same private web host within 45s; no server error, upload, spawned process or exploit success is observed.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R880.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R880", Name = "Public CGI traversal GET followed by admin upload POST", Category = "WebThreat",
            Description = "workbook.R1390: One public client sends GET to /cgi-bin/.%2e/ followed by POST to /admin/upload on same private web host within 45s; no server error, upload, spawned process or exploit success is observed.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "http.method", "http.uri", "http.host", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent observable source predicate.",
                "Bounded per-rule monotonic UTC observation, with no unavailable producer asserted."
            },
            NegativeConditions = new[]
            {
                "Missing, contradictory, duplicate, out-of-order or expired evidence fails closed.",
                "No authenticated identity, file transfer, decoded encrypted content, command execution, configuration or outcome inferred."
            },
            FalsePositives = new[]
            {
                "Approved maintenance, software deployment, diagnostics, administrative sessions and normal traffic may share this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(45), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "public_cgi_encoded_traversal_get_then_admin_upload_post",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R880_PublicTraversalThenAdminPostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.PublicPrivate(r)
                || r.DestinationPort != 80
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253)
                return NoMatch();
            var initial = method == "GET" && uri.StartsWith("/cgi-bin/.%2e/", StringComparison.OrdinalIgnoreCase);
            var followup = method == "POST" && uri == "/admin/upload";
            if (!initial && !followup) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.HttpHost.ToLowerInvariant();
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, initial, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1390", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_cgi_encoded_traversal_get_then_admin_upload_post", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public CGI traversal GET followed by admin upload POST; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

