// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2809.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R884_GitPrivateObjectGetFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R884", Name: "Git-attributed private repository HTTP object GET fanout", Category: "Collection",
            Description: "git-attributed HTTP GET visits four distinct .git/objects paths on one private server within 60s; authenticated SaaS principal, repository confidentiality and unusual download volume are not established.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R884.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R884", Name = "Git-attributed private repository HTTP object GET fanout", Category = "Collection",
            Description = "workbook.R2809: git-attributed HTTP GET visits four distinct .git/objects paths on one private server within 60s; authenticated SaaS principal, repository confidentiality and unusual download volume are not established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process, RuleTelemetryKind.Http },
            RequiredFields = new[] { "process.id", "http.uri", "http.method", "source", "destination", "packet.id" },
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
            MinimumConfidence = 80, WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "git_http_get_four_distinct_object_paths_private_peer",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _distinct = new();
        public R884_GitPrivateObjectGetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 80 || !Research676Evidence.Process(r, "git", "git.exe")
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "GET" || !uri.Contains(".git/objects/", StringComparison.OrdinalIgnoreCase)
                || uri.Length is < 27 or > 240
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253)
                return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId + "|" + r.HttpHost.ToLowerInvariant();
            if (!_distinct.Observe(key, uri.ToLowerInvariant(), r.Id, context.TimestampUtc, 4, 60))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2809", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "git_http_get_four_distinct_object_paths_private_peer", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Git-attributed private repository HTTP object GET fanout; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 4, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

