// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2802.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R877_DockerApiCreateThenStartRequestRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R877", Name: "Docker remote create and start HTTP API requests", Category: "Execution",
            Description: "Same private client sends Docker HTTP/2375 POST /containers/create then a POST /containers/{id}/start to the same daemon within 60s; no image policy, privileged flags or successful deployment is verified.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R877.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R877", Name = "Docker remote create and start HTTP API requests", Category = "Execution",
            Description = "workbook.R2802: Same private client sends Docker HTTP/2375 POST /containers/create then a POST /containers/{id}/start to the same daemon within 60s; no image policy, privileged flags or successful deployment is verified.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "http.method", "http.uri", "source", "destination", "destination.port", "packet.id" },
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
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "same_client_docker_create_post_then_container_start_post",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R877_DockerApiCreateThenStartRequestRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.TcpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.DestinationPort != 2375
                || !WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "POST" || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost.Length > 253)
                return NoMatch();
            var create = uri == "/containers/create";
            var start = uri.StartsWith("/containers/", StringComparison.Ordinal)
                && uri.EndsWith("/start", StringComparison.Ordinal)
                && uri.Length > "/containers//start".Length
                && !uri.Substring("/containers/".Length).Contains("..", StringComparison.Ordinal);
            if (!create && !start) return NoMatch();
            if (!_stages.Observe(r.Source! + "|" + r.Destination!, r.Id, context.TimestampUtc,
                create, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2802", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "same_client_docker_create_post_then_container_start_post", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Docker remote create and start HTTP API requests; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

