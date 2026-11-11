// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source written first; zero tests/builds executed. workbook.R2720.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R894_PublicSshThenWebApiProbeRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R894", Name: "Public source probes SSH then web API login", Category: "Discovery",
            Description: "Same public client SYNs to private SSH/22 then POSTs /api/login on the same private host HTTP/80 within 60s; neither authentication, server operating system, exposed ICS role nor authorization is established.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R894.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R894", Name = "Public source probes SSH then web API login", Category = "Discovery",
            Description = "workbook.R2720: Same public client SYNs to private SSH/22 then POSTs /api/login on the same private host HTTP/80 within 60s; neither authentication, server operating system, exposed ICS role nor authorization is established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination", "destination.port", "http.uri", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Typed IPv4 packet predicate and independent bounded UTC correlation." },
            NegativeConditions = new[] { "Missing, inconsistent, duplicate, out-of-order or expired evidence fails closed.",
                "No trusted identity, host audit, process ancestry, successful operation or malicious outcome inferred." },
            FalsePositives = new[] { "Approved administration, software, troubleshooting or routine service traffic can match." },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "same_public_client_ssh22_syn_then_private_http_api_login_post",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "MaintenanceWindows" },
            RequiredTests = new[] { "positive and benign packet cases", "missing and contradictory fields",
                "duplicate IDs, reverse UTC, expiry", "cooldown", "raw Info excluded", "neighbor independence",
                "unique Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R894_PublicSshThenWebApiProbeRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r) || !Research786NetworkEvidence.PublicPrivate(r))
                return NoMatch();
            var first = Research676Evidence.Syn(r) && r.DestinationPort == 22;
            var second = Research786NetworkEvidence.TcpData(r) && r.DestinationPort == 80
                && WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                && method == "POST" && uri == "/api/login" && !string.IsNullOrWhiteSpace(r.HttpHost)
                && r.HttpHost.Length <= 253;
            if (!first && !second) return NoMatch();
            if (!_stages.Observe(r.Source! + "|" + r.Destination!, r.Id, context.TimestampUtc,
                first, 60)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2720", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "same_public_client_ssh22_syn_then_private_http_api_login_post", "rule"),
                new DetectionEvidenceItem("outcome", "packet_shape_only_authorization_and_security_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Public source probes SSH then web API login; authentication, causality and outcome remain unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_evidence");
                    confidence.AddEvidence(0.33, "owner_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_correlation");
                }, count: 2, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
